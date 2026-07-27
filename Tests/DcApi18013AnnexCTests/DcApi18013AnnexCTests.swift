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

import Testing
@testable import DcApi18013AnnexC
import Foundation
import MdocDataModel18013
import MdocDataTransfer18013

// MARK: - expandSelections with selectedDocumentIds

@Test func expandsToAllDocumentIdsWhenNoSelectionGiven() {
	let selectionsByDocType = [
		"org.iso.18013.5.1.mDL": ["org.iso.18013.5.1": ["family_name"]]
	]
	let documentIdsByDocType = [
		"org.iso.18013.5.1.mDL": ["doc-1", "doc-2", "doc-3"]
	]

	let result = DcApiHandler.expandSelections(for: selectionsByDocType, documentIdsByDocType: documentIdsByDocType, selectedDocumentIds: nil)

	#expect(result.count == 3)
	#expect(result["doc-1"] != nil)
	#expect(result["doc-2"] != nil)
	#expect(result["doc-3"] != nil)
}

@Test func expandsToOnlySelectedDocumentIds() {
	let selectionsByDocType = [
		"org.iso.18013.5.1.mDL": ["org.iso.18013.5.1": ["family_name"]]
	]
	let documentIdsByDocType = [
		"org.iso.18013.5.1.mDL": ["doc-1", "doc-2", "doc-3"]
	]

	let result = DcApiHandler.expandSelections(for: selectionsByDocType, documentIdsByDocType: documentIdsByDocType, selectedDocumentIds: ["doc-2"])

	#expect(result.count == 1)
	#expect(result["doc-2"] == selectionsByDocType["org.iso.18013.5.1.mDL"])
	#expect(result["doc-1"] == nil)
	#expect(result["doc-3"] == nil)
}

@Test func selectsOneDocumentPerDocTypeAcrossMultipleDocTypes() {
	let selectionsByDocType = [
		"org.iso.18013.5.1.mDL": ["org.iso.18013.5.1": ["family_name"]],
		"eu.europa.ec.eudi.pid.1": ["eu.europa.ec.eudi.pid.1": ["age_over_18"]]
	]
	let documentIdsByDocType = [
		"org.iso.18013.5.1.mDL": ["mdl-1", "mdl-2"],
		"eu.europa.ec.eudi.pid.1": ["pid-1", "pid-2"]
	]

	let result = DcApiHandler.expandSelections(for: selectionsByDocType, documentIdsByDocType: documentIdsByDocType, selectedDocumentIds: ["mdl-1", "pid-2"])

	#expect(result.count == 2)
	#expect(result["mdl-1"] != nil)
	#expect(result["pid-2"] != nil)
	#expect(result["mdl-2"] == nil)
	#expect(result["pid-1"] == nil)
}

@Test func excludesAllWhenSelectedIdsMatchNoDocuments() {
	let selectionsByDocType = [
		"org.iso.18013.5.1.mDL": ["org.iso.18013.5.1": ["family_name"]]
	]
	let documentIdsByDocType = [
		"org.iso.18013.5.1.mDL": ["doc-1", "doc-2"]
	]

	let result = DcApiHandler.expandSelections(for: selectionsByDocType, documentIdsByDocType: documentIdsByDocType, selectedDocumentIds: ["unknown"])

	#expect(result.isEmpty)
}

// MARK: - narrowSelectedItems

@Test func narrowKeepsOnlyChosenElements() {
	let selectedItems: [String: [NameSpace: [RequestItem]]] = [
		"doc-1": [
			"org.iso.18013.5.1": [
				RequestItem(elementIdentifier: "family_name"),
				RequestItem(elementIdentifier: "given_name"),
				RequestItem(elementIdentifier: "birth_date")
			]
		]
	]
	let chosen: [String: [String: [String]]] = [
		"doc-1": ["org.iso.18013.5.1": ["family_name", "birth_date"]]
	]

	let result = DcApiHandler.narrowSelectedItems(selectedItems, to: chosen)

	let kept = result["doc-1"]?["org.iso.18013.5.1"]?.map(\.elementIdentifier).sorted()
	#expect(kept == ["birth_date", "family_name"])
}

@Test func narrowDropsNamespaceWhenNoElementsChosen() {
	let selectedItems: [String: [NameSpace: [RequestItem]]] = [
		"doc-1": [
			"org.iso.18013.5.1": [RequestItem(elementIdentifier: "family_name")]
		]
	]
	let chosen: [String: [String: [String]]] = [
		"doc-1": ["org.iso.18013.5.1": []]
	]

	let result = DcApiHandler.narrowSelectedItems(selectedItems, to: chosen)

	#expect(result["doc-1"]?["org.iso.18013.5.1"] == nil)
}

@Test func narrowLeavesDocumentsAbsentFromChosenUnchanged() {
	let selectedItems: [String: [NameSpace: [RequestItem]]] = [
		"doc-1": ["org.iso.18013.5.1": [RequestItem(elementIdentifier: "family_name")]],
		"doc-2": ["org.iso.18013.5.1": [RequestItem(elementIdentifier: "given_name")]]
	]
	let chosen: [String: [String: [String]]] = [
		"doc-1": ["org.iso.18013.5.1": ["family_name"]]
	]

	let result = DcApiHandler.narrowSelectedItems(selectedItems, to: chosen)

	// doc-2 was not in `chosen`, so it is left untouched.
	#expect(result["doc-2"]?["org.iso.18013.5.1"]?.map(\.elementIdentifier) == ["given_name"])
}