//
//  XProtectRuleCatalogTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Listing Apple's rules
/// Pins how Settings > XProtect Rules reads Apple's rule files: each rule from its header to its closing brace, named
/// by its description or else its identifier, with its UUID, report-only when `match_type = 4`, and without the
/// private and global rules. Rule files here are stand-ins shaped as Apple writes them, then this Mac's own.
final class XProtectRuleCatalogTests: XCTestCase {
    /// A rule file's text with what Apple's files hold and more: the import line, private and global rules, tags, a
    /// meta section over many lines and one on a single line, braces in strings, hex strings, regexes and comments,
    /// a string that reads like metas, and a rule without a description.
    private let files = """
        import "hash"

        private rule Macho
        {
            meta:
                description = "private rule to match Mach-O binaries"
            condition:
                uint32(0) == 0xfeedfacf
        }

        global rule Small { condition: filesize < 10MB }

        rule XProtect_MACOS_BRACES : adware dropper
        {
            meta:
                // description = "NOT.A.META"
                description = "MACOS.BRACES"
                uuid = "49BCCB20-498C-4F37-92CF-8CAF1A8C7813"
                reference = "condition: none, // not a comment"
                description = "MACOS.SECOND"
            strings:
                $description = "NOT.THE.NAME"
                $m = "match_type = 4 uuid = 1"
                $a = "}{ \\" }"
                $b = { 4D 5A ?? [2-4] ( 90 | 91 ) }
                $c = /x{2,3}\\}/ /* { */
                $hex = {
                    CA FE BA BE
                }
            condition:
                Macho and any of them // }
        }
        rule NoDescription { strings: $a = "plain" condition: $a } // a comment after its brace

        rule XProtect_HUNT_MACOS_TEST { meta: description = "HUNT.MACOS.TEST" match_type = 4 condition: true }
        """

    /// The scripts file: its own rules, and a private rule whose identifier the other file shares.
    private let scripts = """
        private rule OSACompiledJXA {
            meta:
                description = "MACOS.OSASCRIPT.OSACOMPILEDJXA"
            condition:
                uint32be(0) == 0x4A734F73
        }
        rule XProtect_MACOS_OSASCRIPT_BOTEA {
            meta:
                description = "MACOS.OSASCRIPT.BOTEA"
                uuid = "FAA3D768-953A-4B4F-9EAA-7E967BD38196"
                interpreter = "osascript"
                match_type = 4
            strings:
                $a1 = "https://example/" ascii wide
            condition:
                filesize < 1MB and all of them
        }
        """

    /// Each listed rule from both files, in order, with its name, UUID, file and whether it's report-only.
    func testRulesAreListedWithTheirMetas() {
        let catalog = XProtectRuleCatalog(XProtectRuleSources(
            bundle: URL(fileURLWithPath: "/XProtect.bundle"), version: "5377",
            texts: [.scripts: Data(scripts.utf8), .xprotect: Data(files.utf8)]))
        XCTAssertEqual(catalog.version, "5377")
        XCTAssertEqual(catalog.rules.map(\.identifier), ["XProtect_MACOS_BRACES", "NoDescription",
                                                         "XProtect_HUNT_MACOS_TEST", "XProtect_MACOS_OSASCRIPT_BOTEA"])
        XCTAssertEqual(catalog.rules.map(\.name), ["MACOS.BRACES", "NoDescription", "HUNT.MACOS.TEST",
                                                   "MACOS.OSASCRIPT.BOTEA"])
        XCTAssertEqual(catalog.rules.map(\.uuid), ["49BCCB20-498C-4F37-92CF-8CAF1A8C7813", nil, nil,
                                                   "FAA3D768-953A-4B4F-9EAA-7E967BD38196"])
        XCTAssertEqual(catalog.rules.map(\.isReportOnly), [false, false, true, true])
        XCTAssertEqual(catalog.rules.map(\.file), [.xprotect, .xprotect, .xprotect, .scripts])
        XCTAssertEqual(catalog.rules.map(\.id).last, "XPScripts.yr/XProtect_MACOS_OSASCRIPT_BOTEA")
    }

    /// A rule's source runs from its header line to its closing brace, as written, whatever braces it holds.
    func testASourceIsTheRuleAsWritten() throws {
        let rules = XProtectRuleCatalog.rules(in: files, file: .xprotect)
        let braces = try XCTUnwrap(rules.first)
        XCTAssertTrue(braces.source.hasPrefix("rule XProtect_MACOS_BRACES : adware dropper\n{\n    meta:"))
        XCTAssertTrue(braces.source.hasSuffix("Macho and any of them // }\n}"), braces.source)
        XCTAssertEqual(braces.source.components(separatedBy: "\n").count, 20)
        XCTAssertEqual(rules[1].source, #"rule NoDescription { strings: $a = "plain" condition: $a }"#)
        XCTAssertEqual(rules[2].source, #"rule XProtect_HUNT_MACOS_TEST { meta: description = "HUNT.MACOS.TEST" "#
                       + "match_type = 4 condition: true }")
    }

    /// Metas are read as written, up to the strings: the first of a repeated name, none from a comment, and none
    /// from a string or a value that looks like one.
    func testMetasStopAtTheStrings() {
        let metas = XProtectRuleCatalog.metas(in: XProtectRuleCatalog.rules(in: files, file: .xprotect)[0].source)
        XCTAssertEqual(metas, ["description": "MACOS.BRACES", "uuid": "49BCCB20-498C-4F37-92CF-8CAF1A8C7813",
                               "reference": "condition: none, // not a comment"])
    }

    /// A text with no rules, or one cut off before its brace, lists nothing.
    func testNothingToList() {
        XCTAssertEqual(XProtectRuleCatalog.rules(in: "import \"hash\"\n", file: .xprotect), [])
        XCTAssertEqual(XProtectRuleCatalog.rules(in: "rule Cut { meta: description = \"CUT\"", file: .scripts), [])
    }

    /// This Mac's XProtect bundle lists every rule header that isn't private or global, once per file, each named by
    /// its description, and as many report-only rules as the files say `match_type = 4`.
    func testThisMacsRulesAreConsistent() throws {
        guard let sources = XProtectRuleSources.read() else { throw XCTSkip("This Mac has no XProtect rules.") }
        let catalog = XProtectRuleCatalog(sources)
        XCTAssertEqual(catalog.version, sources.version)
        let texts = sources.texts.mapValues { String(decoding: $0, as: UTF8.self) }
        for (file, text) in texts {
            let listed = catalog.rules.filter { $0.file == file }
            XCTAssertEqual(listed.count, count(#"(?m)^rule\s"#, in: text), file.rawValue)
            XCTAssertEqual(Set(listed.map(\.identifier)).count, listed.count, "\(file.rawValue) repeats a rule")
            XCTAssertTrue(listed.allSatisfy {
                XProtectRuleCatalog.metas(in: $0.source)["description"] == $0.name && $0.source.hasSuffix("}")
            }, file.rawValue)
        }
        XCTAssertFalse(catalog.rules.isEmpty)
        XCTAssertEqual(catalog.rules.filter(\.isReportOnly).count,
                       texts.values.map { count(#"match_type\s*=\s*4\b"#, in: $0) }.reduce(0, +))
    }

    /// How many times a pattern matches.
    ///
    /// - Parameters:
    ///   - pattern: The regular expression.
    ///   - text: The text.
    /// - Returns: The number of matches.
    private func count(_ pattern: String, in text: String) -> Int {
        (try? NSRegularExpression(pattern: pattern))?.numberOfMatches(in: text, range: NSRange(text.startIndex...,
                                                                                               in: text)) ?? 0
    }
}
