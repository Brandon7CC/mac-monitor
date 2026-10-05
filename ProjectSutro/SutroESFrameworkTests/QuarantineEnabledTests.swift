//
//  QuarantineEnabledTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - File Quarantine-aware executables
/// Pins that the byte search in front of ``ProcessHelpers/isQuarantineEnabled(forExecutableAt:signingId:)`` turns away
/// only paths Foundation's `contains(".app")` turned away, and that app bundles are still read.
final class QuarantineEnabledTests: XCTestCase {
    /// Characters that make a non-literal search differ from a byte search: combining marks, precomposed letters,
    /// look-alike dots, a prepended mark, joiners, and other cases.
    private static let alphabet: [String] = [
        ".", "a", "p", "/", "x", "A", "P", "\u{301}", "\u{307}", "\u{E1}", "\u{1E55}", "\u{1E57}", "\u{FF0E}",
        "\u{2024}", "\u{FE52}", "\u{0600}", "\u{200D}", "\u{200B}", "\u{FEFF}", "\u{212A}", "\u{0251}", "\u{0440}",
    ]
    
    /// Wherever `contains(".app")` finds ".app", the bytes are there: on edge cases and on 20,000 random strings.
    func testByteSearchKeepsEverythingContainsFinds() {
        let edges = ["", ".ap", ".app", ".APP", "a.app", "/Applications/Safari.app/Contents/MacOS/Safari",
                     ".app\u{301}", ".a\u{301}pp", ".ap\u{1E55}", "\u{FF0E}app", "\u{0600}.app", ".\u{200D}app",
                     "x.app.app", "/usr/libexec/logd", "Foo.application", ".appx"]
        var generated = edges
        for _ in 0..<20_000 {
            generated.append((0..<Int.random(in: 1...10)).map { _ in Self.alphabet.randomElement()! }.joined())
        }
        for path in generated where path.contains(".app") {
            XCTAssertTrue(ProcessHelpers.hasAppBytes(path), path.unicodeScalars.map { String($0.value, radix: 16) }
                .joined(separator: " "))
        }
        XCTAssertTrue(ProcessHelpers.hasAppBytes(".app"))
        XCTAssertFalse(ProcessHelpers.hasAppBytes(".ap"))
        XCTAssertFalse(ProcessHelpers.hasAppBytes("\u{FF0E}app"))
    }
    
    /// A path outside an app bundle isn't File Quarantine-aware; one inside a bundle is what its Info.plist says.
    ///
    /// - Throws: The error writing the bundles.
    func testAppBundlesAreStillRead() throws {
        let directory = try makeTemporaryDirectory()
        for (name, enabled) in [("OptIn", true), ("OptOut", false)] {
            let contents = directory.appendingPathComponent("\(name).app/Contents", isDirectory: true)
            try FileManager.default.createDirectory(at: contents.appendingPathComponent("MacOS"),
                                                    withIntermediateDirectories: true)
            let plist: [String: Any] = ["LSFileQuarantineEnabled": enabled]
            try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                .write(to: contents.appendingPathComponent("Info.plist"))
        }
        let optIn = directory.appendingPathComponent("OptIn.app/Contents/MacOS/OptIn").path
        let optOut = directory.appendingPathComponent("OptOut.app/Contents/MacOS/OptOut").path
        XCTAssertEqual(ProcessHelpers.isQuarantineEnabled(forExecutableAt: optIn, signingId: "com.example.optin"),
                       .optIn)
        XCTAssertEqual(ProcessHelpers.isQuarantineEnabled(forExecutableAt: optOut, signingId: "com.example.optout"),
                       .disabled)
        let tool = ProcessHelpers.isQuarantineEnabled(forExecutableAt: "/usr/bin/true", signingId: "com.apple.true")
        XCTAssertEqual(tool, .disabled)
    }
}
