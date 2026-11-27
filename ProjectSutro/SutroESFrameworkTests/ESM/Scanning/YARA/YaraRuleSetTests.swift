//
//  YaraRuleSetTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/24/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Compiling and scanning
/// Runs the libyara this Mac's XprotectFramework exports: compiling rule text, scanning bytes, naming matches with
/// Apple's rule class, and saving and loading compiled rules.
final class YaraRuleSetTests: XCTestCase {
    /// The library, or the test is skipped on a Mac without one Mac Monitor knows.
    private func library() throws -> YaraLibrary {
        switch YaraLibrary.shared {
        case .success(let library): return library
        case .failure(let reason): throw XCTSkip("No libyara Mac Monitor knows here: \(reason)")
        }
    }

    /// Compiles rule text that must compile.
    private func compile(_ text: String) throws -> YaraRuleSet {
        let compiled = YaraCompiler.compile(text, with: try library())
        return try XCTUnwrap(compiled.rules, "\(compiled.diagnostics)")
    }

    /// Scans a string's bytes.
    private func scan(_ text: String, with rules: YaraRuleSet) -> YaraRuleSet.Outcome {
        Array(text.utf8).withUnsafeBytes { rules.scan($0, timeout: 5) }
    }

    /// The identifiers of a scan's matches, or a failure.
    private func identifiers(_ outcome: YaraRuleSet.Outcome) -> [String]? {
        guard case .matched(let matches) = outcome else { return nil }
        return matches.map(\.identifier)
    }

    /// This Mac's layout is read, and its identifier sits after the rule's leading fields.
    func testTheLibraryLoads() throws {
        XCTAssertGreaterThan(try library().abi.identifierOffset, 0)
    }

    /// Bytes a rule matches report it, every rule that matches is reported, and bytes nothing matches report none.
    func testScanReportsEveryMatch() throws {
        let rules = try compile("""
        rule First { strings: $a = "mac-monitor-first" condition: $a }
        rule Second { strings: $a = "mac-monitor-second" condition: $a }
        rule Neither { strings: $a = "mac-monitor-neither" condition: $a }
        """)
        XCTAssertEqual(identifiers(scan("x mac-monitor-second y mac-monitor-first", with: rules)).map(Set.init),
                       ["First", "Second"])
        XCTAssertEqual(identifiers(scan("nothing here", with: rules)), [])
        XCTAssertEqual(identifiers(Array<UInt8>().withUnsafeBytes { rules.scan($0, timeout: 5) }), [])
    }

    /// Apple's rule class names a match from its description, and says a `match_type = 4` rule is report only.
    func testMatchesAreNamedAsXProtectNamesThem() throws {
        let rules = try compile("""
        rule Named { meta: description = "MAC.MONITOR.NAMED" strings: $a = "named" condition: $a }
        rule Reported { meta: description = "HUNT.MAC.MONITOR" match_type = 4 strings: $a = "reported" condition: $a }
        rule Bare { strings: $a = "bare" condition: $a }
        """)
        guard case .matched(let matches) = scan("named reported bare", with: rules) else { return XCTFail() }
        let byIdentifier = Dictionary(uniqueKeysWithValues: matches.map { ($0.identifier, $0) })
        XCTAssertEqual(byIdentifier["Named"]?.name, "MAC.MONITOR.NAMED")
        XCTAssertEqual(byIdentifier["Named"]?.isReportOnly, false)
        XCTAssertEqual(byIdentifier["Reported"]?.name, "HUNT.MAC.MONITOR")
        XCTAssertEqual(byIdentifier["Reported"]?.isReportOnly, true)
        XCTAssertNil(byIdentifier["Bare"]?.name)
    }

    /// Rule text with an error makes no rules, and says where the error is, without crashing.
    func testAnErrorIsReportedWithItsLine() throws {
        let compiled = YaraCompiler.compile("rule Fine { condition: true }\nrule Broken { condition: $missing }",
                                            with: try library())
        XCTAssertNil(compiled.rules)
        let error = try XCTUnwrap(compiled.diagnostics.first(where: \.isError))
        XCTAssertEqual(error.line, 2)
        XCTAssertFalse(error.message.isEmpty)
    }

    /// A rule can't include a file, so rule text never makes the compiler read one.
    func testIncludesAreRefused() throws {
        let compiled = YaraCompiler.compile("include \"/etc/hosts\"\nrule R { condition: true }", with: try library())
        XCTAssertNil(compiled.rules)
        XCTAssertTrue(compiled.diagnostics.contains(where: \.isError))
    }

    /// Rules saved to a file load again and match as they did.
    func testSavedRulesLoadAgain() throws {
        let rules = try compile("rule Saved { strings: $a = \"saved-rule\" condition: $a }")
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let writing = open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(writing, 0)
        XCTAssertNoThrow(try rules.save(to: writing))
        close(writing)

        let reading = open(file.path, O_RDONLY | O_CLOEXEC)
        defer { close(reading) }
        let loaded = try YaraRuleSet.load(from: reading, library: try library())
        XCTAssertEqual(identifiers(scan("a saved-rule here", with: loaded)), ["Saved"])
    }

    /// Apple's whole rule set, megabytes of compiled rules, saves and loads through the buffered stream, quickly,
    /// and still matches: libyara moves them a few bytes at a time, which once cost seconds of system calls.
    func testApplesRulesRoundTrip() throws {
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw XCTSkip("This Mac has no XProtect.yara.")
        }
        let rules = try compile(text)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let start = Date()
        let writing = open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        try rules.save(to: writing)
        close(writing)
        let reading = open(file.path, O_RDONLY | O_CLOEXEC)
        defer { close(reading) }
        let loaded = try YaraRuleSet.load(from: reading, library: try library())
        XCTAssertLessThan(Date().timeIntervalSince(start), 1, "Saving and loading took too long.")
        XCTAssertGreaterThan(try FileManager.default.attributesOfItem(atPath: file.path)[.size] as? Int ?? 0, 1 << 20)
        let test = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].joined()
        XCTAssertEqual(identifiers(scan(test, with: loaded)), ["EICAR"])
    }

    /// A file that isn't compiled rules doesn't load.
    func testOtherFilesDontLoad() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("not compiled rules".utf8).write(to: file)
        let reading = open(file.path, O_RDONLY | O_CLOEXEC)
        defer { close(reading) }
        XCTAssertThrowsError(try YaraRuleSet.load(from: reading, library: try library()))
    }

    /// Apple's own XProtect.yara compiles with this Mac's libyara, and its EICAR rule matches the EICAR test file
    /// under Apple's name. The test file is put together here, so no copy of it sits in the repository.
    func testApplesRulesMatchTheTestFile() throws {
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw XCTSkip("This Mac has no XProtect.yara.")
        }
        let rules = try compile(text)
        let test = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].joined()
        guard case .matched(let matches) = scan(test, with: rules) else { return XCTFail() }
        XCTAssertEqual(matches.map(\.identifier), ["EICAR"])
        XCTAssertEqual(matches.first?.name, "OSX.eicar.com.i")
        XCTAssertEqual(identifiers(scan(test + "\n", with: rules)), [])
    }
}
