//
//  IndicatorEditingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What an edit changes
/// Pins the editable fields Settings, `macmonitor indicators edit` and the Security Extension share: which differ,
/// taking only those named, detecting the same whatever the switch and views, tactics typed any way, and a file's
/// entries read as written.
final class IndicatorEditingTests: XCTestCase {
    /// A shipped indicator, and a copy with every editable field changed.
    ///
    /// - Returns: The two.
    /// - Throws: If the shipped indicator isn't there.
    private func everyFieldChanged() throws -> (Indicator, Indicator) {
        let original = try XCTUnwrap(Indicator.defaults.first { $0.tactic != nil && $0.technique != nil })
        var edited = original
        edited.name += " edited"
        edited.description += " More."
        edited.symbol = "star"
        edited.color = original.color == .red ? .blue : .red
        edited.predicate += " AND process.pid > 1"
        edited.tactic = original.tactic == .impact ? .discovery : .impact
        edited.technique = "T1059.002"
        edited.severity = original.severity == .high ? .low : .high
        return (original, edited)
    }

    /// Every editable field that differs is listed, in order. Whether it's on and its views never are.
    func testChangedFieldsListsOnlyEditableFieldsInOrder() throws {
        let (original, edited) = try everyFieldChanged()
        XCTAssertEqual(original.changedFields(to: edited), Indicator.EditableField.allCases)
        XCTAssertEqual(Indicator.EditableField.allCases.map(\.rawValue), [
            "name", "description", "symbol", "color", "predicate", "tactic", "technique", "severity",
        ])
        var switched = original
        switched.isEnabled.toggle()
        switched.tableMarks = original.tableMarks.isEmpty ? [.dot, .symbol] : []
        XCTAssertEqual(original.changedFields(to: switched), [])
        switched.severity = edited.severity
        switched.predicate = edited.predicate
        XCTAssertEqual(original.changedFields(to: switched), [.predicate, .severity])
        XCTAssertEqual(Indicator.EditableField.allCases.filter(\.isRule),
                       [.name, .description, .symbol, .color, .predicate])
    }

    /// `take` copies only the fields named, and keeps the identity, switch and views.
    func testTakeCopiesOnlyTheNamedFields() throws {
        let (original, edited) = try everyFieldChanged()
        var other = edited
        other.id = UUID()
        other.isEnabled.toggle()
        other.tableMarks = original.tableMarks.isEmpty ? [.dot, .symbol] : []
        for field in Indicator.EditableField.allCases {
            var taken = original
            taken.take([field], from: other)
            XCTAssertEqual(original.changedFields(to: taken), [field], field.rawValue)
            XCTAssertEqual(taken.id, original.id)
            XCTAssertEqual(taken.isEnabled, original.isEnabled)
            XCTAssertEqual(taken.views, original.views)
        }
        var all = original
        all.take(Indicator.EditableField.allCases, from: other)
        XCTAssertEqual(all.changedFields(to: edited), [])
        XCTAssertEqual(all.isEnabled, original.isEnabled)
    }

    /// The same detection whatever the identity, switch and views, and not after any editable field changes.
    func testSameDetectionIgnoresTheSwitchAndViews() throws {
        let (original, edited) = try everyFieldChanged()
        var copy = original
        copy.id = UUID()
        copy.isEnabled.toggle()
        copy.tableMarks = original.tableMarks.isEmpty ? .dot : []
        XCTAssertTrue(copy.sameDetection(as: original))
        for field in Indicator.EditableField.allCases {
            var changed = original
            changed.take([field], from: edited)
            XCTAssertFalse(changed.sameDetection(as: original), field.rawValue)
            XCTAssertEqual(changed.sameDetection(as: original), original.changedFields(to: changed).isEmpty)
        }
    }

    /// A tactic is its raw value, ATT&CK identity or name, in any case, with or without spaces, hyphens and
    /// underscores. Anything else is none of them.
    func testTacticsByAnyName() {
        let spellings: [(String, Indicator.Tactic)] = [
            ("persistence", .persistence), ("TA0003", .persistence), ("ta0003", .persistence),
            ("defenseEvasion", .defenseEvasion), ("defense-evasion", .defenseEvasion),
            ("Defense Evasion", .defenseEvasion), ("DEFENSE_EVASION", .defenseEvasion),
            ("command and control", .commandAndControl), ("TA0011", .commandAndControl),
        ]
        for (typed, tactic) in spellings {
            XCTAssertEqual(Indicator.Tactic.named(typed), tactic, typed)
        }
        for typed in ["", " ", "-", "TA9999", "persist", "none"] {
            XCTAssertNil(Indicator.Tactic.named(typed), typed)
        }
        for tactic in Indicator.Tactic.allCases {
            XCTAssertEqual([tactic.rawValue, tactic.identifier, tactic.name].map(Indicator.Tactic.named),
                           [tactic, tactic, tactic])
        }
    }

    /// A file's entries are read as written, in its three shapes, with nothing made up: no identity where it has
    /// none. What isn't an indicator file, or has no indicators, is refused as an import refuses it.
    func testEntriesAreReadAsWritten() throws {
        let one = Data(#"{"severity": "high"}"#.utf8)
        let entries = try IndicatorExchange.entryObjects(from: one)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries.first?.keys.sorted(), ["severity"])
        XCTAssertEqual(try IndicatorExchange.entryObjects(from: Data(#"[{"name": "A"}, {"name": "B"}]"#.utf8))
            .compactMap { $0["name"] as? String }, ["A", "B"])
        let file = try IndicatorExchange.data(of: Array(Indicator.defaults.prefix(2)))
        XCTAssertEqual(try IndicatorExchange.entryObjects(from: file).compactMap { $0["id"] as? String },
                       Indicator.defaults.prefix(2).map(\.id.uuidString))

        let refused: [(String, String)] = [
            ("nope", "The file isn't JSON."),
            (#"{"format": "mutes", "indicators": []}"#, "The file isn't Mac Monitor indicators."),
            (#"{"format": "com.swiftlydetecting.indicators", "version": 2, "indicators": []}"#,
             "The file is from a newer Mac Monitor. Update to import it."),
            (#"{"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": [7]}"#,
             "An indicator in the file isn't a JSON object."),
            (#"{"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": {}}"#,
             "The file's indicators can't be read."),
            ("[]", "The file has no indicators."), ("7", "The file isn't JSON."),
        ]
        for (text, message) in refused {
            let error = thrown(IndicatorExchange.ImportError.self) {
                try IndicatorExchange.entryObjects(from: Data(text.utf8))
            }
            XCTAssertEqual(error?.message, message, text)
        }
    }

    /// Indicators by identity keep the first of any that share one.
    func testByIDKeepsTheFirst() {
        var twin = Indicator.defaults[1]
        twin.id = Indicator.defaults[0].id
        let byID = Indicator.byID([Indicator.defaults[0], twin])
        XCTAssertEqual(byID.count, 1)
        XCTAssertEqual(byID[Indicator.defaults[0].id], Indicator.defaults[0])
        XCTAssertEqual(CompiledIndicators.shippedDefaults.count, Indicator.defaults.count)
    }
}
