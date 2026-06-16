/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import SwiftCBOR
import WalletStorage
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import IdentityDocumentServices
import CryptoKit
import X509
import SwiftHPKE

public actor DcApiHandler {
	let storage: KeyChainStorageService
	var documents: [WalletStorage.Document] = []
	var transactionLogger: (any TransactionLogger)?

	public init(serviceName: String, accessGroup: String, transactionLogger: (any TransactionLogger)? = nil) {
		storage = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		// register default secure areas
		let kcSks = KeyChainSecureKeyStorage(serviceName: serviceName, accessGroup: accessGroup)
		if SecureEnclave.isAvailable { SecureAreaRegistry.shared.register(secureArea: SecureEnclaveSecureArea.create(storage: kcSks)) }
		SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: kcSks))
		self.transactionLogger = transactionLogger
	}

	public func validateRequest(_ request: ISO18013MobileDocumentRequest) async throws -> ([DocClaimsModel], ISO18013MobileDocumentRequest.DocumentRequestSet, [UInt8], String?) {
		var rn: String?
		var kid: [UInt8] = []
		// else {  throw MdocHelpers.makeError(code: .noDocumentToReturn, str: "No authentication certification chain") }
		if let root = request.requestAuthentications.first?.authenticationCertificateChain.first, case let cert = try Certificate(derEncoded: (SecCertificateCopyData(root) as Data).bytes), let aki = try cert.extensions.authorityKeyIdentifier  {
			rn = (try? cert.extensions.subjectAlternativeNames)?.first?.description ?? cert.subject.description
			kid = Array(aki.keyIdentifier ?? [])
		}
		try await loadIssuedCborDocuments()
		let docTypes = documents.compactMap(\.docType)
		// Collect every document-request-set from mandatory presentment requests that
		// references at least one docType we hold, instead of only the first match.
		// This is required for combined presentations (e.g. mDL + PID) where the
		// verifier may split docTypes across multiple sets / presentment requests.
		let matchingSets: [ISO18013MobileDocumentRequest.DocumentRequestSet] = request.presentmentRequests
			.filter { $0.isMandatory }
			.flatMap { $0.documentRequestSets }
			.filter { set in set.requests.contains(where: { docTypes.contains($0.documentType) }) }
		guard let firstSet = matchingSets.first else { throw MdocHelpers.makeError(code: .documents_not_provided) }
		// Union the requested elements across all matching sets, keyed by docType.
		var requestedElementsByDocType: [DocType: [NameSpace: Set<DataElementIdentifier>]] = [:]
		for set in matchingSets {
			let perSet = try Self.requestedElementsByDocType(documentRequestSet: set)
			for (docType, namespaces) in perSet {
				var merged = requestedElementsByDocType[docType] ?? [:]
				for (ns, elements) in namespaces {
					merged[ns, default: []].formUnion(elements)
				}
				requestedElementsByDocType[docType] = merged
			}
		}
		let docClaimsModels: [DocClaimsModel] = try documents.compactMap { document in
			guard let requestedElements = requestedElementsByDocType[document.docType] else { return nil }
			let model = try Self.makeFilteredModel(for: document, requestedElements: requestedElements)
			return model.docClaims.isEmpty ? nil : model
		}
		return (docClaimsModels, firstSet, kid, rn)
	}

	// proposed function in the wwdc video, to be implemented
	public func validateConsistency(request: ISO18013MobileDocumentRequest, rawRequest: IdentityDocumentWebPresentmentRawRequest) async throws {
	}

	public func buildAndEncryptResponse(remoteRawRequest: DcApiExtensionRequest, selectedDocumentIds: Set<String>? = nil, selectedClaimsByDocumentId: [String: [String: [String]]]? = nil, zkSystemRepository: ZkSystemRepository?) async throws -> Data {
		let rawRequest = IdentityDocumentWebPresentmentRawRequest(requestType: .iso18013MobileDocument, requestData: remoteRawRequest.rawRequestData)
		let originUrl = remoteRawRequest.originUrl
		return try await buildAndEncryptResponse(rawRequest: rawRequest, originUrl: originUrl, selectedDocumentIds: selectedDocumentIds, selectedClaimsByDocumentId: selectedClaimsByDocumentId, zkSystemRepository: zkSystemRepository)
	}

	// selectedDocumentIds: if set, include only these documents. selectedClaimsByDocumentId: if set, disclose only these elements per document (docId -> namespace -> [elementId]). Both nil = original behaviour.
	public func buildAndEncryptResponse(rawRequest: IdentityDocumentWebPresentmentRawRequest, originUrl: String?, selectedDocumentIds: Set<String>? = nil, selectedClaimsByDocumentId: [String: [String: [String]]]? = nil, zkSystemRepository: ZkSystemRepository? = nil) async throws -> Data {
		guard let originUrl, let jsonRequest = try? JSONSerialization.jsonObject(with: rawRequest.requestData) as? [String: String], let dReqBase64Url = jsonRequest["deviceRequest"], let deviceRequestData = Data(base64urlEncoded: dReqBase64Url),
			let eiBase64Url = jsonRequest["encryptionInfo"], let eiData = Data(base64urlEncoded: eiBase64Url), let eiCbor = try? CBOR.decode([UInt8](eiData)) else { throw MdocHelpers.makeError(code: .requestDecodeError) }
		let deviceReq = try DeviceRequest(data: [UInt8](deviceRequestData))
		guard case let .array(eiArr) = eiCbor, eiArr.count == 2, case let .map(eiMap) = eiArr[1], case let .map(recPK) = eiMap["recipientPublicKey"], case let .unsignedInt(crv) = recPK[-1], crv == 1, case .unsignedInt(_) = recPK[1], case let .byteString(bx) = recPK[-2], case let .byteString(by) = recPK[-3] else { throw MdocHelpers.makeError(code: .sessionEncryptionNotInitialized) }
		// create input structures
		if documents.count == 0 { try await loadIssuedCborDocuments() }
		let idsToDocData = documents.compactMap { $0.getDataForTransfer() }
		let docTypeToIds = Dictionary(grouping: documents, by: { d in d.docType}).mapValues { docs in docs.map(\.id) }
		var docKeyInfos = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.docKeyInfo))
		var docData = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.doc))
		var documentKeyIndexes = docData.mapValues { _ in 0 }
		for doc0 in documents {
			guard let dkid = docKeyInfos[doc0.id], DocKeyInfo(from: dkid) != nil else { docKeyInfos[doc0.id] = nil; continue }
			let doc = try await storage.loadDocument(id: doc0.id, status: .issued)
			docData[doc0.id] = doc?.data
			documentKeyIndexes[doc0.id] = doc?.keyIndex
		}
		docData = docData.filter { docKeyInfos[$0.key] != nil }
		guard idsToDocData.count > 0 else { throw MdocHelpers.makeError(code: .documents_not_provided) }
		let idsToMetadata = idsToDocData.map(\.metadata)
		let docMetadata = Dictionary(uniqueKeysWithValues: idsToMetadata).compactMapValues {$0}
		let issuerSigned = try docData.mapValues { try IssuerSigned(data: $0.bytes)}
		let privateKeyObjects: [String: CoseKeyPrivate] = try await MdocHelpers.getPrivateKeys(docKeyInfos, documentKeyIndexes)
		let serializedOrigin = originUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		let dcapiInfo = CBOR.array([.utf8String(eiBase64Url), .utf8String(serializedOrigin)])
		let dcapiInfoHash = Self.sha256(data: Data(dcapiInfo.encode()))
		let dcApiHandoverCbor = CBOR.array([.utf8String("dcapi"), .byteString(dcapiInfoHash.bytes)])
		let sessionTranscript = SessionTranscript(handOver: dcApiHandoverCbor)
		let resp1 = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: deviceReq, issuerSigned: issuerSigned, docMetadata: docMetadata, selectedItems: nil, privateKeyObjects: privateKeyObjects, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: [:], zkSystemRepository: zkSystemRepository)
		let selectedItems1 = resp1?.validRequestItems ?? [:]
		var selectedItems = Self.expandSelections(for: selectedItems1, documentIdsByDocType: docTypeToIds, selectedDocumentIds: selectedDocumentIds)
		if let selectedClaimsByDocumentId {
			selectedItems = Self.narrowSelectedItems(selectedItems, to: selectedClaimsByDocumentId)
		}
		let resp = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: deviceReq, issuerSigned: issuerSigned, docMetadata: docMetadata, selectedItems: selectedItems, privateKeyObjects: privateKeyObjects, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: [:], zkSystemRepository: zkSystemRepository)
		guard let resp else { throw MdocHelpers.makeError(code: .noDocumentToReturn) }
		let sessionTranscriptEncoded = sessionTranscript.encode(options: CBOROptions())
		let docDeviceResponse = resp.deviceResponse
		let plainText = docDeviceResponse.encode(options: CBOROptions())
		let docMetadataValues = resp.documentIds.map { id in docMetadata[id] }
		try await transactionLogger?.log(transaction: TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .completed, errorMessage: nil, rawRequest: deviceRequestData, rawResponse: Data(plainText), relyingParty: TransactionLog.RelyingParty(name: originUrl, isVerified: false, certificateChain: [], readerAuth: nil), type: .presentation, dataFormat: .cbor, sessionTranscript: Data(sessionTranscriptEncoded), docMetadata: docMetadataValues))
		// Update key batch info for presented documents to decrement one-time-use count
		try await updateKeyBatchInfoForPresentedDocuments(presentedIds: Array(selectedItems.keys), docKeyInfos: docKeyInfos, documentKeyIndexes: documentKeyIndexes, deviceResponse: resp.deviceResponse)
		// Create the Sender instance and encrypt
		let res = Self.hpkeEncrypt(receiverPublicKeyRepresentation: Data(bx + by), plainText: Data(resp.deviceResponse.encode(options: CBOROptions())), info: Data(sessionTranscriptEncoded))
		let encryptedResponseData = CBOR.map([.utf8String("enc"): .byteString(res[0].bytes), .utf8String("cipherText"): .byteString(res[1].bytes)])
		let encryptedResponse = CBOR.array([.utf8String("dcapi"), encryptedResponseData])
		return Data(encryptedResponse.encode())
	}

	/// Updates key batch info for presented documents to track one-time-use credential consumption
	/// - Parameters:
	///   - presentedIds: Array of document IDs that were presented
	///   - docKeyInfos: Dictionary mapping document IDs to their key info data
	///   - documentKeyIndexes: Dictionary mapping document IDs to the key index used for presentation
	///  - deviceResponse: The DeviceResponse sent to the device, used to determine if the credential policy is one-time-use
	private func updateKeyBatchInfoForPresentedDocuments(presentedIds: [String], docKeyInfos: [String: Data?], documentKeyIndexes: [String: Int], deviceResponse: DeviceResponse) async throws {
		let zkDocTypes = Set(deviceResponse.zkDocuments?.map(\.documentData.docType) ?? [])
		for id in presentedIds {
			guard let docKeyInfoData = docKeyInfos[id], let dkid = docKeyInfoData,
				  let dki = DocKeyInfo(from: dkid),
				  let keyIndex = documentKeyIndexes[id] else { continue }
			let secureArea = SecureAreaRegistry.shared.get(name: dki.secureAreaName)
			// Delete credential and key if one-time-use policy, but not for ZK documents
			let docType = documents.first(where: { $0.id == id })?.docType
			let isZkDocument = docType.map { zkDocTypes.contains($0) } ?? false
			if dki.credentialPolicy == .oneTimeUse && !isZkDocument {
				try await storage.deleteDocumentCredential(id: id, index: keyIndex)
				try await secureArea.deleteKeyBatch(id: id, startIndex: keyIndex, batchSize: 1)
				_ = try await secureArea.updateKeyBatchInfo(id: id, keyIndex: keyIndex)
			}
		}
	}

	private func loadIssuedCborDocuments() async throws {
		guard let docs = try? await storage.loadDocuments(status: .issued) else { throw MdocHelpers.makeError(code: .documents_not_provided) }
		documents = docs.filter { $0.docDataFormat == .cbor }
	}

	static func hpkeEncrypt(receiverPublicKeyRepresentation: Data, plainText: Data, info: Data) -> [Data] {
		let receiverKey = try! P256.KeyAgreement.PublicKey(rawRepresentation: receiverPublicKeyRepresentation)
		let recipientPublicKey = try! PublicKey(der: Bytes(receiverKey.derRepresentation))
		let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
		let (enc, cipherText) = try! theSuite.seal(publicKey: recipientPublicKey, info: info.bytes, pt: plainText.bytes, aad: [])
		return [Data(enc), Data(cipherText)]
	}

	public static func sha256(data: Data) -> Data {
			let hashed = SHA256.hash(data: data)
			return Data(hashed)
	}

	// Keeps only the chosen elements per document. selectedItems maps docId -> namespace -> [RequestItem]; chosen maps docId -> namespace -> [elementId]. Documents absent from chosen are left unchanged.
	static func narrowSelectedItems(_ selectedItems: [String: [NameSpace: [RequestItem]]], to chosen: [String: [String: [String]]]) -> [String: [NameSpace: [RequestItem]]] {
		var result = selectedItems
		for (docId, namespaces) in selectedItems {
			guard let keptByNamespace = chosen[docId] else { continue }
			var narrowed: [NameSpace: [RequestItem]] = [:]
			for (namespace, items) in namespaces {
				let kept = Set(keptByNamespace[namespace] ?? [])
				let filtered = items.filter { kept.contains($0.elementIdentifier) }
				if !filtered.isEmpty { narrowed[namespace] = filtered }
			}
			result[docId] = narrowed
		}
		return result
	}

	static func expandSelections<Value>(for selectionsByDocType: [DocType: Value], documentIdsByDocType: [DocType: [String]], selectedDocumentIds: Set<String>? = nil) -> [String: Value] {
		var selectionsByDocumentId: [String: Value] = [:]
		for (docType, selection) in selectionsByDocType {
			for documentId in documentIdsByDocType[docType] ?? [] {
				if let selectedDocumentIds, !selectedDocumentIds.contains(documentId) { continue }
				selectionsByDocumentId[documentId] = selection
			}
		}
		return selectionsByDocumentId
	}

	static func requestedElementsByDocType(documentRequestSet: ISO18013MobileDocumentRequest.DocumentRequestSet) throws -> [DocType: [NameSpace: Set<DataElementIdentifier>]] {
		var requestedElementsByDocType: [DocType: [NameSpace: Set<DataElementIdentifier>]] = [:]
		for docRequest in documentRequestSet.requests {
			var requestedElementsByNamespace = requestedElementsByDocType[docRequest.documentType] ?? [:]
			for (nameSpace, elementInfoByIdentifier) in docRequest.namespaces {
				var requestedElements = requestedElementsByNamespace[nameSpace] ?? []
				requestedElements.formUnion(elementInfoByIdentifier.keys)
				requestedElementsByNamespace[nameSpace] = requestedElements
			}
			requestedElementsByDocType[docRequest.documentType] = requestedElementsByNamespace
		}
		return requestedElementsByDocType
	}

	static func makeFilteredModel(for document: WalletStorage.Document, requestedElements: [NameSpace: Set<DataElementIdentifier>]) throws -> DocClaimsModel {
		let issuerSigned = try IssuerSigned(data: document.data.bytes)
		let metadata = DocMetadata(from: document.metadata)
		let docKeyInfo = DocKeyInfo(from: document.docKeyInfo)
		let matchingClaims = filter(docClaims: documentClaims(from: issuerSigned, metadata: metadata), requestedElements: requestedElements)
		let matchingNamespaces = requestedElements.keys.filter { namespace in
			matchingClaims.contains(where: { $0.namespace == namespace })
		}
		return DocClaimsModel(configuration: DocClaimsModelConfiguration(id: document.id, createdAt: document.createdAt, docType: document.docType, displayName: document.displayName ?? metadata?.getDisplayName(nil), display: metadata?.display, issuerDisplay: metadata?.issuerDisplay, credentialIssuerIdentifier: metadata?.credentialIssuerIdentifier, configurationIdentifier: metadata?.configurationIdentifier, validFrom: issuerSigned.validFrom, validUntil: issuerSigned.validUntil, statusIdentifier: issuerSigned.issuerAuth.statusIdentifier, credentialsUsageCounts: nil, credentialPolicy: docKeyInfo?.credentialPolicy ?? metadata?.credentialOptions?.credentialPolicy ?? .rotateUse, secureAreaName: docKeyInfo?.secureAreaName ?? metadata?.keyOptions?.secureAreaName, modifiedAt: document.modifiedAt, docClaims: matchingClaims, docDataFormat: document.docDataFormat, hashingAlg: nil, nameSpaces: matchingNamespaces))
	}

	static func documentClaims(from issuerSigned: IssuerSigned, metadata: DocMetadata?) -> [DocClaim] {
		guard let nameSpaceItems = DocClaimsModel.getCborSignedItems(issuerSigned) else { return [] }
		var docClaims: [DocClaim] = []
		let cmd = metadata?.claims?.convertToCborClaimMetadata(nil)
		DocClaimsModel.extractCborClaims(nameSpaceItems, &docClaims, cmd?.displayNames, cmd?.mandatory)
		return docClaims
	}

	static func filter(docClaims: [DocClaim], requestedElements: [NameSpace: Set<DataElementIdentifier>]) -> [DocClaim] {
		docClaims.filter { claim in
			guard let namespace = claim.namespace, let elements = requestedElements[namespace] else { return false }
			return elements.contains(claim.name)
		}
	}

}