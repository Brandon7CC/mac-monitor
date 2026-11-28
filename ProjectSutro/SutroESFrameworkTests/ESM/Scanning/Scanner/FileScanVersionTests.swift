//
//  FileScanVersionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Results remembered by version
/// Pins what the scanner's memory answers (``FileScanMemory``): a lookup by a version's content ignores its change
/// time, a close of another version forgets that content's answer, and only a result that describes the content
/// answers such a lookup.
final class FileScanVersionTests: XCTestCase {
    /// The memory forgets a content's answer once a close names another version of it, even one never scanned, as a
    /// busy close isn't.
    func testTheMemoryForgetsAContentAnotherCloseRewrote() throws {
        let file = try scannedFile("main-marker")
        var memory = FileScanMemory(capacity: 8)
        let first = FileScanVersion(file.info)
        memory.remember(YaraScan(status: YaraScan.scanned, xprotectVersion: "5377"), files: [.xprotect], for: first)
        var chmodded = file.info
        chmodded.st_ctimespec.tv_sec += 1
        XCTAssertNotNil(memory.result(for: FileScanVersion(chmodded), covering: [.xprotect], anyChangeTime: true))
        XCTAssertNil(memory.result(for: FileScanVersion(chmodded), covering: [.xprotect]), "Not that version")
        memory.forgetContent(changedBy: FileScanVersion(chmodded))
        XCTAssertNil(memory.result(for: FileScanVersion(chmodded), covering: [.xprotect], anyChangeTime: true))
        XCTAssertNotNil(memory.result(for: first, covering: [.xprotect]), "A close of the first still has it.")
        memory.remember(.notScanned(YaraScan.unreadable), files: [.xprotect], for: first)
        XCTAssertNil(memory.result(for: first, covering: [], anyChangeTime: true),
                     "A result that doesn't describe the content never answers an exec.")
    }
}
