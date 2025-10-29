// The Swift Programming Language
// https://docs.swift.org/swift-book

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

public class DcApiHandler {
	let storage: KeyChainStorageService
	var documents: [WalletStorage.Document] = []
	
	public init(serviceName: String, accessGroup: String) {
		storage = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		// register default secure areas
		let kcSks = KeyChainSecureKeyStorage(serviceName: serviceName, accessGroup: accessGroup)
		if SecureEnclave.isAvailable { SecureAreaRegistry.shared.register(secureArea: SecureEnclaveSecureArea.create(storage: kcSks)) }
		SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: kcSks))
	}
	
	public func validateRequest(_ request: ISO18013MobileDocumentRequest) async throws -> (ISO18013MobileDocumentRequest.DocumentRequestSet, [UInt8], String?) {
		var rn: String?
		var kid: [UInt8] = []
		// else {  throw MdocHelpers.makeError(code: .noDocumentToReturn, str: "No authentication certification chain") }
		if let root = request.requestAuthentications.first?.authenticationCertificateChain.first, case let cert = try Certificate(derEncoded: (SecCertificateCopyData(root) as Data).bytes), let aki = try cert.extensions.authorityKeyIdentifier  {
			rn = (try? cert.extensions.subjectAlternativeNames)?.first?.description ?? cert.subject.description
			kid = Array(aki.keyIdentifier ?? [])
		}
		guard let docs = try? await storage.loadDocuments(status: .issued) else { throw MdocHelpers.makeError(code: .documents_not_provided) }
		documents = docs
		let docTypes = docs.compactMap(\.docType)
		let reqFind: (ISO18013MobileDocumentRequest.DocumentRequestSet) -> Bool = { $0.requests.allSatisfy({dr in docTypes.contains(dr.documentType)}) }
		let drFind: ([ISO18013MobileDocumentRequest.DocumentRequestSet]) -> ISO18013MobileDocumentRequest.DocumentRequestSet? = { drs in drs.first(where: reqFind) }
		let prSet = request.presentmentRequests.filter({ pr in pr.isMandatory && drFind(pr.documentRequestSets) != nil })
		guard let pr = prSet.first, let drs = drFind(pr.documentRequestSets), !drs.requests.isEmpty else { throw MdocHelpers.makeError(code: .documents_not_provided) }
		return (drs, kid, rn)
	}
	
	public func validateConsistency(request: ISO18013MobileDocumentRequest, rawRequest: IdentityDocumentWebPresentmentRawRequest) async throws {
	}
	
	public func validateRawRequest(rawRequest: IdentityDocumentWebPresentmentRawRequest) async throws {
	}
	
	public func buildAndEncryptResponse(request: ISO18013MobileDocumentRequest, rawRequest: IdentityDocumentWebPresentmentRawRequest, originUrl: String?) async throws -> Data {
		guard let originUrl, let jsonRequest = try? JSONSerialization.jsonObject(with: rawRequest.requestData) as? [String: String], let dReqBase64Url = jsonRequest["deviceRequest"], let deviceRequestData = Data(base64urlEncoded: dReqBase64Url),
			let eiBase64Url = jsonRequest["encryptionInfo"], let eiData = Data(base64urlEncoded: eiBase64Url), let eiCbor = try? CBOR.decode([UInt8](eiData)) else { throw MdocHelpers.makeError(code: .requestDecodeError) }
		let deviceReq = try DeviceRequest(data: [UInt8](deviceRequestData))
		guard case let .array(eiArr) = eiCbor, eiArr.count == 2, case let .map(eiMap) = eiArr[1], case let .map(recPK) = eiMap["recipientPublicKey"], case let .unsignedInt(crv) = recPK[-1], crv == 1, case .unsignedInt(_) = recPK[1], case let .byteString(bx) = recPK[-2], case let .byteString(by) = recPK[-3] else { throw MdocHelpers.makeError(code: .sessionEncryptionNotInitialized) }
		// create input structures
		let idsToDocData = documents.compactMap { $0.getDataForTransfer() }
		let docTypeToIds = Dictionary(grouping: documents, by: { d in d.docType ?? ""}).mapValues { $0.first!.id }
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
		let docMetadata = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.metadata)).compactMapValues {$0}
		let issuerSigned = try docData.mapValues { try IssuerSigned(data: $0.bytes)}
		let privateKeyObjects: [String: CoseKeyPrivate] = Dictionary(uniqueKeysWithValues: docKeyInfos.compactMap {
			guard let dki = DocKeyInfo(from: $0.value) else { return nil }
			guard let keyIndex = documentKeyIndexes[$0.key] else { return nil }
			return ($0.key, CoseKeyPrivate(privateKeyId: $0.key, index: keyIndex, secureArea: SecureAreaRegistry.shared.get(name: dki.secureAreaName)))
		})
		let serializedOrigin = originUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		let dcapiInfo = CBOR.array([.utf8String(eiBase64Url), .utf8String(serializedOrigin)])
		let dcapiInfoHash = Self.sha256(data: Data(dcapiInfo.encode()))
		let dcApiHandoverCbor = CBOR.array([.utf8String("dcapi"), .byteString(dcapiInfoHash.bytes)])
		let sessionTranscript = SessionTranscript(handOver: dcApiHandoverCbor)
		let resp1 = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: deviceReq, issuerSigned: issuerSigned, docMetadata: docMetadata, selectedItems: nil, privateKeyObjects: privateKeyObjects, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: [:])
		let selectedItems1 = resp1?.validRequestItems ?? [:]
		let selectedItems = Dictionary(uniqueKeysWithValues: selectedItems1.compactMap { (key: String, value: [NameSpace : [RequestItem]]) -> (String, [NameSpace : [RequestItem]])? in	if let id = docTypeToIds[key] { (id, value) } else { nil }	})
		let resp = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: deviceReq, issuerSigned: issuerSigned, docMetadata: docMetadata, selectedItems: selectedItems, privateKeyObjects: privateKeyObjects, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: [:])
		guard let resp else { throw MdocHelpers.makeError(code: .noDocumentToReturn) }
		// Create the Sender instance and encrypt
		let plainText = resp.deviceResponse.encode(options: CBOROptions())
		let sessionTranscriptEncoded = sessionTranscript.encode(options: CBOROptions()) 
		let res = Self.hpkeEncrypt(receiverPublicKeyRepresentation: Data(bx + by), plainText: Data(plainText), info: Data(sessionTranscriptEncoded))
		let encryptedResponseData = CBOR.map([.utf8String("enc"): .byteString(res[0].bytes), .utf8String("cipherText"): .byteString(res[1].bytes)])
		let encryptedResponse = CBOR.array([.utf8String("dcapi"), encryptedResponseData])
		return Data(encryptedResponse.encode())
	}
	
	class func hpkeEncrypt(receiverPublicKeyRepresentation: Data, plainText: Data, info: Data) -> [Data] {
		let receiverKey = try! P256.KeyAgreement.PublicKey(rawRepresentation: receiverPublicKeyRepresentation)
		let recipientPublicKey = try! PublicKey(der: Bytes(receiverKey.derRepresentation))
		let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
		let (enc, cipherText) = try! theSuite.seal(publicKey: recipientPublicKey, info: info.bytes, pt: plainText.bytes, aad: [])
		return [Data(enc), Data(cipherText)]
	}
	
	public class func sha256(data: Data) -> Data {
			let hashed = SHA256.hash(data: data)
			return Data(hashed)
	}
	
}


