/*
 * Copyright (c) 2026 European Commission
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

import CryptoKit
import Foundation
import Testing
import SwiftCBOR
@testable import DcApi18013AnnexC

/// A website sends the EncryptionInfo. A malformed value must not crash the wallet.
struct EncryptionInfoTests {
	private let key = P256.KeyAgreement.PrivateKey().publicKey

	private func encryptionInfo(
		tag: String = "dcapi", kty: UInt64 = 2, crv: UInt64 = 1, x: [UInt8]? = nil, y: [UInt8]? = nil
	) -> CBOR {
		let raw = [UInt8](key.rawRepresentation)
		let coseKey: CBOR = [1: .unsignedInt(kty), -1: .unsignedInt(crv), -2: .byteString(x ?? Array(raw[0..<32])), -3: .byteString(y ?? Array(raw[32..<64]))]
		return [.utf8String(tag), ["nonce": .byteString([1, 2, 3]), "recipientPublicKey": coseKey]]
	}

	@Test func validKeyIsAccepted() throws {
		let parsed = try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo())
		#expect(parsed.rawRepresentation == key.rawRepresentation)
		let sealed = try DcApiHandler.hpkeEncrypt(receiverKey: parsed, plainText: Data("response".utf8), info: Data("transcript".utf8))
		#expect(sealed[0].count == 65)
	}

	@Test func wrongTagThrows() {
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(tag: "openid4vp")) }
	}

	@Test func wrongKeyTypeOrCurveThrows() {
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(kty: 1)) }
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(crv: 2)) }
	}

	@Test func shortCoordinateThrows() {
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(x: [UInt8](repeating: 1, count: 31))) }
	}

	@Test func pointNotOnTheCurveThrows() {
		let zero = [UInt8](repeating: 0, count: 32)
		let one = [UInt8](repeating: 0, count: 31) + [1]
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(x: zero, y: zero)) }
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: encryptionInfo(x: one, y: one)) }
	}

	@Test func missingKeyThrows() {
		let info: CBOR = [.utf8String("dcapi"), ["nonce": .byteString([1])]]
		#expect(throws: NSError.self) { try DcApiHandler.recipientPublicKey(encryptionInfo: info) }
	}
}
