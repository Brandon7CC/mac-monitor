//
//  XProtectRulesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/24/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Loading Apple's rules
/// Pins how Apple's rules are found and loaded: the XProtect bundle with the higher version, compiled rules kept per
/// key and reused, a new key compiling again and removing the old file, and a rule file that can't compile reported
/// without stopping the other. Rule files here are small stand-ins written to temporary bundles.
final class XProtectRulesTests: XCTestCase {
    /// The library, or the test is skipped.
    private func library() throws -> YaraLibrary {
        guard case .success(let library) = YaraLibrary.shared else { throw XCTSkip("No libyara here.") }
        return library
    }

    /// A temporary XProtect bundle with a version and rule files.
    private func makeBundle(version: String, files: [XProtectRuleFile: String]) throws -> URL {
        let bundle = try makeTemporaryDirectory(prefix: "XProtectRulesTests").appendingPathComponent("XProtect.bundle")
        let resources = bundle.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let info: NSDictionary = ["CFBundleShortVersionString": version]
        XCTAssertTrue(info.write(to: bundle.appendingPathComponent("Contents/Info.plist"), atomically: true))
        for (file, text) in files {
            try Data(text.utf8).write(to: resources.appendingPathComponent(file.rawValue))
        }
        return bundle
    }

    /// A cache in a fresh 0700 directory the user running the test owns.
    private func makeCache() throws -> XProtectRuleCache {
        XProtectRuleCache(directory: try makeTemporaryDirectory(prefix: "XProtectRulesTests", mode: 0o700),
                          owner: getuid())
    }

    /// Rule text for a stand-in rule file with one rule.
    private func rule(_ name: String) -> String {
        "rule \(name) { strings: $a = \"\(name.lowercased())-marker\" condition: $a }"
    }

    /// The bundle with the higher version wins, a tie goes to the first, and a bundle without XProtect.yara is
    /// passed over.
    func testTheHigherVersionWins() throws {
        let old = try makeBundle(version: "5300", files: [.xprotect: rule("Old")])
        let new = try makeBundle(version: "5377", files: [.xprotect: rule("New"), .scripts: rule("Scripts")])
        let empty = try makeBundle(version: "9999", files: [.scripts: rule("Lone")])
        let sources = try XCTUnwrap(XProtectRuleSources.read(from: [old, new, empty]))
        XCTAssertEqual(sources.bundle, new)
        XCTAssertEqual(sources.version, "5377")
        XCTAssertEqual(sources.texts[.scripts], Data(rule("Scripts").utf8))
        XCTAssertEqual(XProtectRuleSources.read(from: [old, new])?.bundle, new)
        XCTAssertEqual(XProtectRuleSources.read(from: [new, try makeBundle(version: "5377", files: [
            .xprotect: rule("Twin")])])?.bundle, new)
        XCTAssertNil(XProtectRuleSources.read(from: [empty]))
        XCTAssertEqual(sources.digest(of: .scripts)?.count, 64)
        XCTAssertNil(XProtectRuleSources.read(from: [old])?.digest(of: .scripts))
    }

    /// Each rule file compiles once into the cache, and the next load reuses it without compiling.
    func testCompiledRulesAreReused() throws {
        let library = try library()
        let cache = try makeCache()
        let sources = try XCTUnwrap(XProtectRuleSources.read(from: [
            try makeBundle(version: "5377", files: [.xprotect: rule("Main"), .scripts: rule("Script")])]))
        var compiles = 0
        let compile: (Data, Int32) throws -> [YaraDiagnostic] = { text, descriptor in
            compiles += 1
            let compiled = YaraCompiler.compile(String(decoding: text, as: UTF8.self), with: library)
            try XCTUnwrap(compiled.rules).save(to: descriptor)
            return compiled.diagnostics
        }
        let first = XProtectRules.load(sources, library: library, cache: cache, build: "TEST1", compile: compile)
        XCTAssertEqual(compiles, 2)
        XCTAssertEqual(first.version, "5377")
        XCTAssertEqual(first.problems, [:])
        let main = try XCTUnwrap(first.sets[.xprotect])
        XCTAssertEqual(Array("main-marker".utf8).withUnsafeBytes { main.scan($0, timeout: 5) },
                       .matched([YaraMatch(identifier: "Main", name: nil, matchType: 11)]))

        let again = XProtectRules.load(sources, library: library, cache: cache, build: "TEST1", compile: compile)
        XCTAssertEqual(compiles, 2, "The cached rules were loaded.")
        XCTAssertEqual(Set(again.sets.keys), [.xprotect, .scripts])

        _ = XProtectRules.load(sources, library: library, cache: cache, build: "TEST2", compile: compile)
        XCTAssertEqual(compiles, 4, "A new macOS build compiles again.")
        let kept = try FileManager.default.contentsOfDirectory(atPath: cache.directory.path).sorted()
        XCTAssertEqual(kept.count, 2, "The old build's files were removed: \(kept)")
        XCTAssertTrue(kept.allSatisfy { $0.hasPrefix("xprotect-") && $0.hasSuffix(".yarc") })
    }

    /// A rule file that doesn't compile is reported, and the other still loads.
    func testOneFileFailingLeavesTheOther() throws {
        let library = try library()
        let sources = try XCTUnwrap(XProtectRuleSources.read(from: [
            try makeBundle(version: "5377", files: [.xprotect: rule("Main"), .scripts: "rule Broken {"])]))
        let rules = XProtectRules.load(sources, library: library, cache: try makeCache(), build: "TEST") { text, out in
            let compiled = YaraCompiler.compile(String(decoding: text, as: UTF8.self), with: library)
            guard let set = compiled.rules else {
                throw XProtectRuleCompiler.Failure.ended(status: 65, diagnostics: compiled.diagnostics)
            }
            try set.save(to: out)
            return compiled.diagnostics
        }
        XCTAssertEqual(Set(rules.sets.keys), [.xprotect])
        let problem = try XCTUnwrap(rules.problems[.scripts])
        XCTAssertTrue(problem.hasPrefix("XPScripts.yr didn't compile: the compiler ended with status 65"), problem)
    }

    /// A kept file that isn't compiled rules is moved aside, and the rules are compiled again.
    func testDamagedRulesAreCompiledAgain() throws {
        let library = try library()
        let cache = try makeCache()
        let sources = try XCTUnwrap(XProtectRuleSources.read(from: [
            try makeBundle(version: "5377", files: [.xprotect: rule("Main")])]))
        let digest = try XCTUnwrap(sources.digest(of: .xprotect))
        let key = XProtectRuleCache.key(for: .xprotect, digest: digest, abi: library.abi, build: "TEST")
        try cache.store(for: .xprotect, key: key).write(Data("damaged".utf8))
        var compiles = 0
        let rules = XProtectRules.load(sources, library: library, cache: cache, build: "TEST") { text, out in
            compiles += 1
            let compiled = YaraCompiler.compile(String(decoding: text, as: UTF8.self), with: library)
            try XCTUnwrap(compiled.rules).save(to: out)
            return []
        }
        XCTAssertEqual(compiles, 1)
        XCTAssertNotNil(rules.sets[.xprotect])
    }

    /// The key changes with each thing that compiled rules depend on.
    func testTheKeyCoversWhatTheRulesDependOn() {
        let abi = YaraABI(generation: .yara4, identifierOffset: 8)
        let key = XProtectRuleCache.key(for: .xprotect, digest: "aa", abi: abi, build: "26B131")
        XCTAssertEqual(key.count, 16)
        XCTAssertEqual(key, XProtectRuleCache.key(for: .xprotect, digest: "aa", abi: abi, build: "26B131"))
        let others = [
            XProtectRuleCache.key(for: .scripts, digest: "aa", abi: abi, build: "26B131"),
            XProtectRuleCache.key(for: .xprotect, digest: "ab", abi: abi, build: "26B131"),
            XProtectRuleCache.key(for: .xprotect, digest: "aa", abi: YaraABI(generation: .yara3, identifierOffset: 136),
                                  build: "26B131"),
            XProtectRuleCache.key(for: .xprotect, digest: "aa", abi: abi, build: "26B123"),
        ]
        XCTAssertFalse(others.contains(key))
        XCTAssertFalse(XProtectRuleCache.currentBuild.isEmpty)
    }
}
