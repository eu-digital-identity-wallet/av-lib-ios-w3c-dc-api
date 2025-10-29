// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "DcApi18013AnnexC",
	platforms: [.macOS(.v26), .iOS(.v26), .watchOS(.v26)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "DcApi18013AnnexC",
			targets: ["DcApi18013AnnexC"]
		)
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-log.git", from: "1.6.3"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git", exact: "0.8.3"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-storage.git", exact: "0.8.0"),
		.package(url: "https://github.com/leif-ibsen/SwiftHPKE", from: "2.8.0"),
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "DcApi18013AnnexC",
			dependencies: [
				.product(
					name: "MdocDataTransfer18013", package: "eudi-lib-ios-iso18013-data-transfer"),
				.product(name: "WalletStorage", package: "eudi-lib-ios-wallet-storage"),
				.product(name: "Logging", package: "swift-log"),
				"SwiftHPKE",
			]),
		.testTarget(
			name: "DcApi18013AnnexCTests",
			dependencies: ["DcApi18013AnnexC"]
		),
	]
)
