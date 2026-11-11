//
//  IndicatorFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The indicator file and its limits
/// Pins the file the Security Extension keeps the Mac's indicators in, and the limits it holds every saved file and
/// request to: the set's size, one identity each, predicate lengths, field caps, event types this build knows, and
/// what the compiled set may cost.
final class IndicatorFileTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// A file reads back as written: an edited shipped indicator, one someone added with its severity, and a
    /// deleted shipped one that stays deleted. It names its version and keeps the saved delta under `saved`.
    func testAFileRoundTrips() throws {
        var indicators = Indicator.defaults
        indicators[0].isEnabled = false
        indicators[1].predicate += " AND process.is_platform_binary == NO"
        indicators.remove(at: 2)
        indicators.append(ownIndicator("Mine", Self.exec, severity: .high))
        let data = try XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded())
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["version"] as? Int, 1)
        XCTAssertNotNil(object["saved"] as? [String: Any])

        let read = try IndicatorFile.decode(data)
        XCTAssertEqual(read.version, IndicatorFile.currentVersion)
        XCTAssertEqual(read.saved.indicators, indicators)
        XCTAssertEqual(read.saved.indicators.last?.severity, .high)
        XCTAssertFalse(read.saved.indicators.contains { $0.id == Indicator.defaults[2].id }, "Deleted stays deleted")
    }

    /// A newer file is unsupported, and anything that isn't an indicator file is malformed.
    func testNewerAndMalformedFiles() {
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.decode(Data(#"{"version": 2}"#.utf8)) },
                       .unsupportedVersion(2))
        let malformed = ["nope", "[]", #"{"saved": {"entries": []}}"#, #"{"version": true, "saved": {}}"#,
                         #"{"version": 0, "saved": {"entries": []}}"#, #"{"version": 1}"#,
                         #"{"version": 1, "saved": 7}"#]
        for text in malformed {
            let error = thrown(IndicatorFileError.self) { try IndicatorFile.decode(Data(text.utf8)) }
            guard case .malformed? = error else { return XCTFail("\(text): \(String(describing: error))") }
        }
    }

    /// A set past 2,048 indicators, or with one identity twice, is refused, and so is a predicate past 4,096
    /// characters. A predicate of 4,096 characters, more of them in bytes, isn't.
    func testTheSetsLimits() {
        let many = (0...IndicatorLimits.maxIndicators).map { ownIndicator("\($0)", Self.exec) }
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validate(many) },
                       .tooManyIndicators(IndicatorLimits.maxIndicators + 1))
        XCTAssertNoThrow(try IndicatorFile.validate(Array(many.dropLast())))

        let first = ownIndicator("First", Self.exec)
        var twin = ownIndicator("Twin", Self.exec)
        twin.id = first.id
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validate([first, twin]) },
                       .duplicateID(first.id, "Twin"))

        let long = ownIndicator("Long", Self.exec + String(repeating: " ", count: 4_096))
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validate([long]) },
                       .predicateTooLong("Long"))
        let wide = ownIndicator("Wide", String(repeating: "é", count: IndicatorLimits.maxPredicateLength))
        XCTAssertNoThrow(try IndicatorFile.validate([wide]))
    }

    /// What a request brings is checked further: an event type this build doesn't know is refused, alone or beside
    /// one it knows, nested under `OR` or `NOT`, or compared with `!=`, and so is a field past its cap. A predicate
    /// that names no type, or doesn't parse, joins: the set keeps it and lists why it can't run.
    func testIncomingIndicators() {
        let unknown = ownIndicator("Unknown", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validateIncoming([unknown]) },
                       .unknownEventTypes("Unknown", ["ES_EVENT_TYPE_NOTIFY_NOPE"]))
        let partly = ownIndicator("Partly", #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_X"}"#)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validateIncoming([partly]) },
                       .unknownEventTypes("Partly", ["ES_EVENT_TYPE_X"]))
        let nested = ownIndicator("Nested", Self.exec
            + #" AND (es_event_type == "ES_EVENT_TYPE_NOTIFY_EXCE" OR process.is_platform_binary == NO)"#)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validateIncoming([nested]) },
                       .unknownEventTypes("Nested", ["ES_EVENT_TYPE_NOTIFY_EXCE"]))
        let negated = ownIndicator("Negated", Self.exec
            + #" AND NOT es_event_type IN {"ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_FORKK"}"#)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validateIncoming([negated]) },
                       .unknownEventTypes("Negated", ["ES_EVENT_TYPE_NOTIFY_FORKK"]))
        let unequal = ownIndicator("Unequal", Self.exec + #" AND es_event_type != "ES_EVENT_TYPE_NOTIFY_OPN""#)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validateIncoming([unequal]) },
                       .unknownEventTypes("Unequal", ["ES_EVENT_TYPE_NOTIFY_OPN"]))
        let knownEverywhere = ownIndicator("Known", Self.exec
            + #" AND NOT (es_event_type == "ES_EVENT_TYPE_NOTIFY_FORK""#
            + #" OR es_event_type != "ES_EVENT_TYPE_NOTIFY_EXEC")"#)
        XCTAssertNoThrow(try IndicatorFile.validateIncoming([knownEverywhere]))

        var named = ownIndicator(String(repeating: "n", count: Indicator.Limits.name + 1), Self.exec)
        guard case .pastLimit? = thrown(IndicatorFileError.self, by: { try IndicatorFile.validateIncoming([named]) })
        else { return XCTFail("A long name joined") }
        named.name = "Short"
        named.technique = "T12"
        guard case .pastLimit? = thrown(IndicatorFileError.self, by: { try IndicatorFile.validateIncoming([named]) })
        else { return XCTFail("A bad technique joined") }

        let untyped = ownIndicator("Untyped", #"process.executable.name == "curl""#)
        let unreadable = ownIndicator("Unreadable", "this isn't a predicate (")
        XCTAssertNoThrow(try IndicatorFile.validateIncoming([untyped, unreadable]))
    }

    /// A compiled set may run 256 rules on one event type and no more. Rules that are off don't count.
    func testTheRulesOnOneType() {
        let rules = (0...IndicatorLimits.maxRulesPerType).map {
            ownIndicator("\($0)", Self.exec + #" AND process.executable.name == "\#($0)""#)
        }
        let past = CompiledIndicators(rules)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validate(past) },
                       .tooManyRules(type: "ES_EVENT_TYPE_NOTIFY_EXEC", count: IndicatorLimits.maxRulesPerType + 1))
        var lastOff = rules
        lastOff[lastOff.count - 1].isEnabled = false
        XCTAssertNoThrow(try IndicatorFile.validate(CompiledIndicators(lastOff)))
    }

    /// A compiled set may have 65,536 nodes in all, across its distinct programs.
    func testTheNodesInAll() throws {
        /// About 200 nodes each, every one distinct, split over two types to stay under the per-type cap.
        let rules = (0..<330).map { index -> Indicator in
            let type = index.isMultiple(of: 2) ? "ES_EVENT_TYPE_NOTIFY_EXEC" : "ES_EVENT_TYPE_NOTIFY_OPEN"
            let terms = (0..<200).map { #"context == "\#($0)""# }.joined(separator: " OR ")
            return ownIndicator("\(index)", #"es_event_type == "\#(type)" AND target_path == "\#(index)" AND ("#
                                + terms + ")")
        }
        let compiled = CompiledIndicators(rules)
        XCTAssertTrue(compiled.problems.isEmpty, "\(compiled.problems.first?.reason ?? "")")
        XCTAssertGreaterThan(compiled.nodeCount, IndicatorLimits.maxNodes)
        XCTAssertEqual(thrown(IndicatorFileError.self) { try IndicatorFile.validate(compiled) },
                       .tooManyNodes(compiled.nodeCount))
        XCTAssertNoThrow(try IndicatorFile.validate(CompiledIndicators(Array(rules.prefix(100)))))
    }

    /// Every problem says which indicator, and which limit, in a sentence.
    func testEveryProblemIsASentence() {
        let id = UUID()
        let errors: [IndicatorFileError] = [
            .unsupportedVersion(2), .malformed("It isn't a JSON object."), .tooManyIndicators(3_000),
            .duplicateID(id, "Twin"), .predicateTooLong("Long"), .pastLimit("Named", "Its name is too long."),
            .unknownEventTypes("Unknown", ["X"]), .tooManyNodes(70_000), .tooManyRules(type: "EXEC", count: 300),
        ]
        for error in errors {
            XCTAssertTrue(error.description.hasSuffix("."), error.description)
        }
        XCTAssertTrue(IndicatorFileError.duplicateID(id, "Twin").description.contains(id.uuidString))
    }
}
