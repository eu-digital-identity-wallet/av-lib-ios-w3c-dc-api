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
import MdocDataModel18013
import SwiftCBOR

/// Carries a request to the main app or a web service for processing.
/// Requests containing zero-knowledge system specifications are forwarded because
/// processing them can exceed the identity provider extension's memory budget.
public struct DcApiExtensionRequest: Sendable, Codable {
	/// Returns nil unless the request decodes, contains zero-knowledge system specifications, and has an origin URL.
	public init?(rawRequestData: Data, originUrl: String?) {
        guard let jsonRequest = try? JSONSerialization.jsonObject(with: rawRequestData) as? [String: String], let dReqBase64Url = jsonRequest["deviceRequest"], let deviceRequestData = Data(base64urlEncoded: dReqBase64Url), let deviceRequest = try? DeviceRequest(data: [UInt8](deviceRequestData)) else { return nil }
		guard deviceRequest.docRequests
			.first(where: { $0.itemsRequest.requestInfo?.zkRequest?.systemSpecs != nil }) != nil, originUrl != nil else { return nil }
		self.rawRequestData = rawRequestData
		self.originUrl = originUrl
	}

	public var rawRequestData: Data
	public var originUrl: String?
}

public enum SharedDefaultKey: String, Sendable {
    case deviceToken
    case fcmToken
    case dcApiRawRequestData
    case dcApiResponseData
}
