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

@Test func filtersDocClaimsByRequestedNamespaceAndElement() {
	let requestedElements: [NameSpace: Set<DataElementIdentifier>] = [
		"org.iso.18013.5.1": ["family_name"],
		"org.iso.18013.5.1.aamva": ["organ_donor"]
	]
	let claims = [
		DocClaim(name: "family_name", displayName: nil, dataValue: .string("Doe"), stringValue: "Doe", namespace: "org.iso.18013.5.1"),
		DocClaim(name: "given_name", displayName: nil, dataValue: .string("Jane"), stringValue: "Jane", namespace: "org.iso.18013.5.1"),
		DocClaim(name: "organ_donor", displayName: nil, dataValue: .boolean(true), stringValue: "true", namespace: "org.iso.18013.5.1.aamva"),
		DocClaim(name: "age_over_18", displayName: nil, dataValue: .boolean(true), stringValue: "true", namespace: "eu.europa.ec.eudi.pid.1")
	]

	let filteredClaims = DcApiHandler.filter(docClaims: claims, requestedElements: requestedElements)

	#expect(filteredClaims.count == 2)
	#expect(filteredClaims.map(\.name).sorted() == ["family_name", "organ_donor"])
}

@Test func expandsSelectionsToAllDocumentIdsForADocType() {
	let selectionsByDocType = [
		"org.iso.18013.5.1.mDL": [
			"org.iso.18013.5.1": ["family_name", "given_name"]
		]
	]
	let documentIdsByDocType = [
		"org.iso.18013.5.1.mDL": ["doc-1", "doc-2"],
		"org.iso.18013.5.1.mVR": ["doc-3"]
	]

	let expandedSelections = DcApiHandler.expandSelections(for: selectionsByDocType, documentIdsByDocType: documentIdsByDocType)

	#expect(expandedSelections.count == 2)
	#expect(expandedSelections["doc-1"] == selectionsByDocType["org.iso.18013.5.1.mDL"])
	#expect(expandedSelections["doc-2"] == selectionsByDocType["org.iso.18013.5.1.mDL"])
	#expect(expandedSelections["doc-3"] == nil)
}
