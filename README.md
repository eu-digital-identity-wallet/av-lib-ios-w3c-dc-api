# DcApi18013AnnexC

A Swift library implementing the W3C Digital Credentials API (DcApi) with ISO 18013-5 Annex C compliance for secure mobile document verification on iOS platforms.

## Overview

This library enables iOS applications to participate in online mobile document (mdoc) verification processes using the W3C's Digital Credentials API protocol. Currently, it is compatible with applications using the [Eudi Wallet Kit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit) with minimum version v0.17.0.

## Usage

1. Add an "Identity Document Provider" extension target to your iOS app project.
2. Add an SPM dependency to `DcApi18013AnnexC` from XCode "Package Dependencies" tab. The package URL is `https://github.com/eu-digital-identity-wallet/av-lib-ios-w3c-dc-api.git`. Add the package to the extension target.
3. Add the "Keychain Sharing" capability in your iOS app from the "Sign and Capabilities" tab and configure a keychain access group. Use the access group in your main app when [initializing](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-kit/documentation/eudiwalletkit/eudiwallet/init(storageservice:servicename:accessgroup:trustedreadercertificates:userauthenticationrequired:openid4vpconfig:openid4vciconfigurations:networking:logfilename:secureareas:transactionlogger:modelfactory:)) the EudiWallet class.
4. Register your age verification document in you main app by using the [`IdentityDocumentProviderRegistrationStore`](https://developer.apple.com/documentation/identitydocumentservices/identitydocumentproviderregistrationstore). Use an empty array for the `supportedAuthorityKeyIdentifiers` parameter.
5. Add the "Keychain Sharing" capability to your Identity Document Provider extension target and use the same access group as your main app.
6. Add the "Digital Credentials API - Mobile Document Provider" capability to your main app and check the "EU Age verification" option.
7. In your Identity Document Provider extension target, import the `DcApi18013AnnexC` library and initialize the `DcApiHandler` with the same access group as your main app.

```swift
@main
struct ProviderExtension: IdentityDocumentProvider {
	let dcApiHandler = DcApiHandler(serviceName: "myService", accessGroup: "AppStoreTeamID.groupName")
	
	var body: some IdentityDocumentRequestScene {
		ISO18013MobileDocumentRequestScene { context in
			// Insert your view here
			RequestAuthorizationView(context: context, dcApiHandler: dcApiHandler)
		}
	}
```	

A sample implementation of the `RequestAuthorizationView` is the following:
```swift
import SwiftUI
import IdentityDocumentServices
import IdentityDocumentServicesUI
import DcApi18013AnnexC
import MdocDataModel18013
import WalletStorage

struct RequestAuthorizationView: View {
	let context: ISO18013MobileDocumentRequestContext
	let dcApiHandler: DcApiHandler
	@State var websiteName: String?
	@State var requestSet: ISO18013MobileDocumentRequest.DocumentRequestSet?
	@State var errorMessage: String?
	
	var body: some View {
		VStack(alignment: .center) {
			if let requestSet, let websiteName {
				Text(websiteName).font(.headline).padding(.bottom, 6)
				List {
					VStack(alignment: .leading) {
						ForEach(requestSet.requests, id: \.documentType) { rs in
							Text(rs.documentType).font(.title)
							let namespaces = Array(rs.namespaces.keys)
							ForEach(namespaces, id: \.self) { ns in
								Text(ns).font(.title2)
								let elements = Array(rs.namespaces[ns]!.keys)
								ForEach(elements, id: \.self) { el in
									Text(el).fontWeight(rs.namespaces[ns]![el]!.isRetaining ? .bold : .thin)
								}
							}
						}
					}
				}
				if let errorMessage { Text(verbatim: errorMessage).foregroundStyle(.red) }
				HStack(alignment: .bottom, spacing: 40) {
					Button {
						context.cancel()
					} label: {
						Label("Cancel", systemImage: "x.circle")
					}.buttonStyle(.bordered)
					if errorMessage == nil {
						Button {
							Task { try await self.acceptVerification() }
						} label: {
							Label("Accept", systemImage: "checkmark.seal")
						}.buttonStyle(.borderedProminent).glassEffect(.regular)
					}
				}
			} else {
				ContentUnavailableView("Cannot validate request", image: "externaldrive.fill.trianglebadge.exclamationmark")
			}
		}.padding() // vstack
		.task {
			do {
				let (set, _, rn) = try await dcApiHandler.validateRequest(context.request)
				requestSet = set
				websiteName = context.requestingWebsiteOrigin?.absoluteString ?? rn ?? "Website name not available"
			} catch {
				errorMessage = String(describing: error)
			}
		}
	} // body
	
	func acceptVerification() async throws {
		try await context.sendResponse { rawRequest in
			try await dcApiHandler.validateConsistency(request: context.request, rawRequest: rawRequest)
			// validate the signatures
			try await dcApiHandler.validateRawRequest(rawRequest: rawRequest)
			let responseData = try await dcApiHandler.buildAndEncryptResponse(request: context.request, rawRequest: rawRequest, originUrl: context.requestingWebsiteOrigin?.absoluteString)
			return ISO18013MobileDocumentResponse(responseData: responseData)
		}
	}
} // end view
```

## Dependencies

- **EUDI Libraries**: European Digital Identity Wallet standard libraries
  - `eudi-lib-ios-iso18013-data-transfer`
  - `eudi-lib-ios-wallet-storage`
- **Swift-Log**: Structured logging support

## Standards Compliance

- **ISO 18013-5**: Mobile driving licence standard (mDL)
- **ISO 18013-7 Annex C**: Mobile driving licence (mDL) addon functions, Digital Credentials API integration
- **W3C Digital Credentials API**: Web standard for credential requests
- **RFC 9180**: HPKE encryption standard

## Resources
- [Verify identity documents on the web - WWDC25 - Videos](https://developer.apple.com/videos/play/wwdc2025/232/)
- [Requesting a mobile document on the web](https://developer.apple.com/documentation/IdentityDocumentServices/Requesting-a-mobile-document-on-the-web)