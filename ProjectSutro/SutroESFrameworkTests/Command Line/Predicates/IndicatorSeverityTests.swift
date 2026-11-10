//
//  IndicatorSeverityTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Severity
/// Pins an indicator's severity: every shipped one has its own, a missing or unknown one decodes as medium, it's saved
/// with a shipped indicator only when someone changed it, and it never makes an edit of the rule. Then the field
/// limits an indicator decodes within.
final class IndicatorSeverityTests: XCTestCase {
    /// Every shipped indicator has the severity its evidence earns: an XProtect detection and a file a File
    /// Quarantine-aware app leaves unquarantined are high, 18 are medium and 23 low. The table names every shipped
    /// indicator, so a new one has to be given its severity here.
    func testDefaultsHaveSeverities() throws {
        let expected: [IndicatorSeverity: Set<String>] = [
            .high: ["XProtect detection", "Unquarantined file from a File Quarantine-aware app"],
            .medium: ["New executable", "Mach-O written", "Scheduled job added", "SSH access modified",
                      "Launch job loaded", "Plug-in installed", "Terminal startup command",
                      "Configuration profile installed", "Login hook set", "Dylib inserted", "Authentication modified",
                      "Browser extension sideloaded", "Folder Action attached", "Reflective loading",
                      "Password checked with dscl", "TCC database modified", "Remote thread created",
                      "Hidden Mach-O executed"],
            .low: ["Background item added", "AppleScript / JXA", "Login", "Adhoc signed", "Unsigned", "Ran a script",
                   "Download tool", "Non-Apple driver opened", "Plist modified", "Quarantine removed",
                   "Keychain opened", "Shell startup file modified", "Archive written", "AppleScript written",
                   "Unsigned code resolved a name", "Elevated to root", "Task port retrieved", "Process traced",
                   "Code signature invalidated", "HID device opened", "Background item removed",
                   "BTM database modified", "Hidden Mach-O written"],
        ]
        XCTAssertEqual(expected.mapValues(\.count), [.high: 2, .medium: 18, .low: 23])
        let shipped = Dictionary(grouping: Indicator.defaults, by: \.severity).mapValues { Set($0.map(\.name)) }
        XCTAssertEqual(shipped, expected)
        XCTAssertLessThan(IndicatorSeverity.low, .medium)
        XCTAssertLessThan(IndicatorSeverity.medium, .high)
        XCTAssertEqual(IndicatorSeverity.allCases.map(\.name), ["Low", "Medium", "High"])
    }

    /// One shared without a severity, or with one this build doesn't know, is medium; one with a severity keeps it,
    /// and it's encoded.
    func testMissingOrUnknownSeverityIsMedium() throws {
        let decoder = JSONDecoder()
        let bare = #"{"name": "Mine", "predicate": "TRUEPREDICATE""#
        XCTAssertEqual(try decoder.decode(Indicator.self, from: Data((bare + "}").utf8)).severity, .medium)
        XCTAssertEqual(try decoder.decode(Indicator.self, from: Data((bare + #", "severity": "critical"}"#).utf8))
            .severity, .medium)
        XCTAssertEqual(try decoder.decode(Indicator.self, from: Data((bare + #", "severity": 3}"#).utf8)).severity,
                       .medium)
        let high = try decoder.decode(Indicator.self, from: Data((bare + #", "severity": "high"}"#).utf8))
        XCTAssertEqual(high.severity, .high)
        let encoded = try jsonObject(encoding: high)
        XCTAssertEqual(encoded["severity"] as? String, "high")
        XCTAssertEqual(try IndicatorExchange.indicators(from: IndicatorExchange.data(of: [high])).first?.severity,
                       .high)
    }

    /// A shipped indicator's severity follows the build unless someone changed it: only a change is saved in its
    /// reference, and changing it isn't an edit of its rule.
    func testSeverityFollowsTheBuildUnlessChanged() throws {
        var indicators = Indicator.defaults
        XCTAssertTrue(indicators[0].hasSameRule(as: {
            var other = indicators[0]; other.severity = .low; return other
        }()))
        let untouched = try entries(of: XCTUnwrap(SavedIndicators(indicators).encoded()))
        XCTAssertNil(untouched[0]["severity"])
        indicators[0].severity = .low
        let changed = try XCTUnwrap(SavedIndicators(indicators).encoded())
        let saved = try entries(of: changed)
        XCTAssertEqual(saved[0]["severity"] as? String, "low")
        XCTAssertNotNil(saved[0]["default"])
        var later = Indicator.defaults
        later[0].predicate += " AND process.pid > 1"
        later[1].severity = .high
        let read = try XCTUnwrap(SavedIndicators(data: changed, defaults: later)?.indicators)
        XCTAssertEqual(read[0].severity, .low)
        XCTAssertEqual(read[0].predicate, later[0].predicate)
        XCTAssertEqual(read[1].severity, .high)
    }

    /// A shipped indicator someone edited, saved in full before severities, keeps the shipped one's.
    func testEditedShippedIndicatorKeepsItsSeverity() throws {
        let shipped = try XCTUnwrap(Indicator.defaults.first { $0.severity == .high })
        var edited = shipped
        edited.predicate += " AND process.pid > 1"
        var entry = try jsonObject(encoding: edited)
        entry["severity"] = nil
        let data = try JSONSerialization.data(withJSONObject: ["entries": [entry], "deleted": []])
        let read = try XCTUnwrap(SavedIndicators(data: data)?.indicators.first { $0.id == shipped.id })
        XCTAssertEqual(read.predicate, edited.predicate)
        XCTAssertEqual(read.severity, .high)
    }
}


// MARK: - Limits
extension IndicatorSeverityTests {
    /// Every shipped indicator and built-in mark is within the limits.
    func testShippedIndicatorsAreWithinTheLimits() {
        for indicator in Indicator.defaults + Indicator.builtInMarks {
            XCTAssertNil(indicator.limitProblem, indicator.name)
        }
    }

    /// A name, description, symbol or technique past its limit doesn't decode, and says which.
    func testFieldsPastTheirLimitsDontDecode() throws {
        let base = Indicator(name: "Mine", description: "", symbol: "star", color: .red, predicate: "TRUEPREDICATE",
                             technique: "T1059.002")
        let changes: [(String, (inout Indicator) -> Void)] = [
            ("name", { $0.name = String(repeating: "n", count: Indicator.Limits.name + 1) }),
            ("description", {
                $0.description = String(repeating: "\u{E9}", count: Indicator.Limits.descriptionBytes / 2 + 1)
            }),
            ("name", { $0.name = "e" + String(repeating: "\u{301}", count: 100_000) }),
            ("symbol", { $0.symbol = String(repeating: "s", count: Indicator.Limits.symbol + 1) }),
            ("symbol", { $0.symbol = "s" + String(repeating: "\u{301}", count: Indicator.Limits.symbol) }),
            ("technique", { $0.technique = "T1059 (AppleScript)" }),
            ("technique", { $0.technique = "TA0003" }),
        ]
        XCTAssertNoThrow(try JSONDecoder().decode(Indicator.self, from: JSONEncoder().encode(base)))
        for (field, change) in changes {
            var indicator = base
            change(&indicator)
            XCTAssertTrue(indicator.limitProblem?.contains(field) == true, "\(field): \(indicator.limitProblem ?? "")")
            XCTAssertThrowsError(try JSONDecoder().decode(Indicator.self, from: JSONEncoder().encode(indicator)), field)
        }
        var atLimits = base
        atLimits.name = String(repeating: "n", count: Indicator.Limits.name)
        atLimits.description = String(repeating: "e", count: Indicator.Limits.descriptionBytes)
        atLimits.technique = "T1059"
        XCTAssertNil(atLimits.limitProblem)
    }

    /// A shipped indicator's saved reference can't carry a technique a full entry couldn't: one past the limit, or
    /// one that isn't a string, keeps the shipped technique, and `null` clears it.
    func testReferenceTechniqueIsValidated() throws {
        let shipped = try XCTUnwrap(Indicator.defaults.first { $0.technique != nil })
        let cases: [(Any, String?)] = [
            ("T1059 (AppleScript)", shipped.technique), (String(repeating: "T", count: 100_000), shipped.technique),
            (42, shipped.technique), ("T1059.002", "T1059.002"), (NSNull(), nil),
        ]
        for (technique, expected) in cases {
            let reference: [String: Any] = ["default": shipped.id.uuidString, "technique": technique]
            let data = try JSONSerialization.data(withJSONObject: ["entries": [reference], "deleted": []])
            let read = try XCTUnwrap(SavedIndicators(data: data)?.indicators.first { $0.id == shipped.id })
            XCTAssertEqual(read.technique, expected, "\(technique)")
            XCTAssertNil(read.limitProblem, "\(technique)")
        }
    }

    /// The Indicators popover lists High first, then Medium, then Low, and by name within each, as Finder sorts.
    func testThePopoverOrdersBySeverityThenName() {
        let names = [("b", IndicatorSeverity.low), ("a", .low), ("Item 10", .high), ("item 9", .high), ("m", .medium)]
        let indicators = names.map { ownIndicator($0.0, "TRUEPREDICATE", severity: $0.1) }
        XCTAssertEqual(Indicator.bySeverity(indicators).map(\.name), ["item 9", "Item 10", "m", "a", "b"])
        XCTAssertEqual(Indicator.bySeverity([]), [])
    }

    /// - Parameter data: Saved indicators.
    /// - Returns: Their entries.
    /// - Throws: A failure when they aren't saved indicators.
    private func entries(of data: Data) throws -> [[String: Any]] {
        let saved = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(saved["entries"] as? [[String: Any]])
    }
}
