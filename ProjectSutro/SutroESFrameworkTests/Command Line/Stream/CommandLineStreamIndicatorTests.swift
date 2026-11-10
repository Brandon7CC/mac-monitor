//
//  CommandLineStreamIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - macmonitor stream --indicator, end to end
/// Pins `macmonitor stream`'s indicators: each record lists the verdicts the Security Extension stamped its event
/// with, and only those; `--indicator` takes a name, ignoring case, or an ID, and is checked against the Mac's set on
/// the stream's own connection before the stream starts. One no event can match stops it (64), and a Security
/// Extension that has no indicators stops it with "Update the Security Extension" (69). A record also lists what the
/// Security Extension couldn't rule out, under `indicators_undetermined`.
final class CommandLineStreamIndicatorTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private var savedIndicators: SavedIndicatorSet?
    /// A scope that suppresses nothing these events hold.
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)
    /// An indicator every exit matches.
    private let everyExit = Indicator(name: "Every exit", description: "", symbol: "star", color: .red,
                                      predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXIT""#, severity: .low)

    /// A mute set and an indicator set in fresh directories, the indicator set with ``everyExit`` added.
    ///
    /// - Throws: If a directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
        let indicators = try makeSavedIndicatorSet()
        XCTAssertEqual(indicators.send(IndicatorRequest(.add, indicators: [everyExit])).status, .ok)
        savedIndicators = indicators
    }

    /// The in-process Security Extension, building real events and stamping them with the indicator set.
    ///
    /// - Returns: The harness.
    private func makeHarness() -> StreamHarness {
        StreamHarness(savedMutes: savedMutes, serializer: MessageSerializer(), savedIndicators: savedIndicators)
    }

    /// Stream exits as JSONL, with a filter, and deliver some once the stream has started.
    ///
    /// - Parameters:
    ///   - indicators: The `--indicator` values.
    ///   - count: How many exits to deliver.
    ///   - harness: The harness.
    /// - Returns: The stream, still running.
    /// - Throws: An `XCTest` failure if no stream started.
    private func streamExits(indicators: [String], count: UInt64, in harness: StreamHarness) throws
        -> StreamCommandRun {
        var filter = StreamFilter()
        filter.indicators = indicators
        let run = StreamCommandRun(harness: harness, formatter: .jsonl([ExportEncoder(model: eventModel)]),
                                   scope: nobody, filter: filter)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_EXIT]
        invocation.filter = filter
        run.start(invocation)
        XCTAssertTrue(waitUntil { !run.diagnostics.all.isEmpty }, "The stream never started.")
        let client = try XCTUnwrap(harness.factories.last?.clients.first)
        (1...count).forEach { client.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: $0, global: $0)) }
        return run
    }

    /// Without `--indicator`, each record lists what the Security Extension matched as it captured the event, with
    /// its severity, evaluated by the Security Extension: macmonitor matches nothing itself.
    func testRecordsListTheStampedVerdicts() throws {
        let harness = makeHarness()
        let run = try streamExits(indicators: [], count: 2, in: harness)
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 })
        for line in run.output.lines {
            let hits = try XCTUnwrap(try jsonObject(Data(line.utf8))["indicators"] as? [[String: Any]])
            XCTAssertEqual(hits.map { $0["name"] as? String }, ["Every exit"])
            XCTAssertEqual(hits.first?["severity"] as? String, "low")
            XCTAssertEqual(hits.first?["evaluated_by"] as? String, "security_extension")
            XCTAssertEqual(hits.first?["default"] as? Bool, false)
        }
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
    }

    /// A modified close the Security Extension's scan budget couldn't decide comes over XPC with the indicator it
    /// couldn't rule out, and its record lists it under `indicators_undetermined`, with its reason, and not as a hit.
    /// A predicate can name the key: one on it writes only that close, of it and a close the set decides.
    func testRecordsListTheUndeterminedIndicators() throws {
        let ends = ownIndicator("Ends", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" AND "#
                                + #"target_path ENDSWITH[c] "needle""#)
        XCTAssertEqual(savedIndicators?.send(IndicatorRequest(.add, indicators: [ends])).status, .ok)
        for predicates in [[], [#"ANY indicators_undetermined.name == "Ends""#]] {
            let harness = makeHarness()
            var filter = StreamFilter()
            filter.predicates = try predicates.map { try StreamFilter.Predicate($0) }
            let run = StreamCommandRun(harness: harness, formatter: .jsonl([ExportEncoder(model: eventModel)]),
                                       scope: nobody, filter: filter)
            var invocation = StreamInvocation()
            invocation.events = [ES_EVENT_TYPE_NOTIFY_CLOSE]
            invocation.filter = filter
            run.start(invocation)
            XCTAssertTrue(waitUntil { !run.diagnostics.all.isEmpty }, "The stream never started.")
            let file = try XCTUnwrap(harness.factories.last).client(.file)
            let long = "/tmp/\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "needle"
            /// Modified, since a stream leaves out unmodified closes.
            file.deliver(closeMessage(modified: true, path: long, seq: 1, global: 1))
            file.deliver(closeMessage(modified: true, path: "/tmp/needle", seq: 2, global: 2))
            let count = predicates.isEmpty ? 2 : 1
            XCTAssertTrue(waitUntil { run.output.lines.count == count }, "\(run.output.lines.count) lines")
            let records = try run.output.lines.map { try jsonObject(Data($0.utf8)) }
            let listed = try XCTUnwrap(records.first?["indicators_undetermined"] as? [[String: Any]])
            let entry = try XCTUnwrap(listed.first { $0["name"] as? String == "Ends" }, "\(listed)")
            XCTAssertEqual(entry["reason"] as? String, "scan_budget")
            XCTAssertEqual(entry["evaluated_by"] as? String, "security_extension")
            let hits = (records.first?["indicators"] as? [[String: Any]])?.map { $0["name"] as? String }
            XCTAssertEqual(hits?.contains("Ends"), false)
            if records.count == 2 {
                XCTAssertNil(records[1]["indicators_undetermined"])
                let decided = (records[1]["indicators"] as? [[String: Any]])?.map { $0["name"] as? String }
                XCTAssertEqual(decided?.contains("Ends"), true)
            }
            run.command.stop()
            XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        }
    }

    /// `--indicator` by name, ignoring case, or by ID writes the events whose records list it. One that names an
    /// indicator exits don't match writes none of them, as filtered.
    func testIndicatorByNameOrID() throws {
        for reference in ["EVERY exit", everyExit.id.uuidString.lowercased()] {
            let harness = makeHarness()
            let run = try streamExits(indicators: [reference], count: 3, in: harness)
            XCTAssertTrue(waitUntil { run.output.lines.count == 3 }, reference)
            run.command.stop()
            XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        }
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let harness = makeHarness()
        let run = try streamExits(indicators: [plist.id.uuidString], count: 3, in: harness)
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        XCTAssertEqual(run.output.lines, [])
        XCTAssertTrue(run.diagnostics.all.last?.contains("(3 filtered out)") == true, "\(run.diagnostics.all)")
    }

    /// An `--indicator` no indicator has, or one that's off, stops the stream before it starts, with 64.
    func testAnIndicatorThatCantMatchStopsTheStream() throws {
        XCTAssertEqual(savedIndicators?.send(IndicatorRequest(.setEnabled, ids: [everyExit.id], enabled: false))
            .status, .ok)
        for reference in ["Every exitt", "every exit"] {
            let harness = makeHarness()
            var filter = StreamFilter()
            filter.indicators = [reference]
            let run = StreamCommandRun(harness: harness, formatter: .jsonl([ExportEncoder(model: eventModel)]),
                                       scope: nobody, filter: filter)
            var invocation = StreamInvocation()
            invocation.filter = filter
            run.start(invocation)
            XCTAssertTrue(waitUntil { !run.reported.isEmpty }, reference)
            guard case .failed(let failure)? = run.reported.first else { return XCTFail("\(run.reported)") }
            XCTAssertEqual(failure.exit, .usage, reference)
            XCTAssertTrue(harness.factories.isEmpty, "\(reference) started a stream")
            XCTAssertEqual(run.reported.count, 1)
        }
    }

    /// Which `--indicator` values can match: one an indicator that's on has, unless the Security Extension can run
    /// none of those that are on.
    func testWhichIndicatorsCanMatch() throws {
        var off = everyExit
        off.id = UUID()
        off.name = "Off"
        off.isEnabled = false
        var unrun = everyExit
        unrun.id = UUID()
        unrun.name = "Unrun"
        let reply = IndicatorReply(status: .ok, indicators: [everyExit, off, unrun],
                                   problems: [IndicatorReply.Problem(id: unrun.id, reason: "It names no type.")])
        XCTAssertNil(StreamCommand.indicatorProblem(["every EXIT", everyExit.id.uuidString], in: reply))
        XCTAssertEqual(StreamCommand.indicatorProblem(["Every exit", "Nope"], in: reply)?.message, """
            No indicator has the ID or name “Nope”. Run 'macmonitor indicators list' to see them.
            """)
        XCTAssertEqual(StreamCommand.indicatorProblem(["off"], in: reply), CommandLineFailure(.usage, """
            “Off” is off, so no event matches it. Turn it on with 'sudo macmonitor indicators enable \
            \(off.id.uuidString)'.
            """))
        XCTAssertEqual(StreamCommand.indicatorProblem([unrun.id.uuidString], in: reply), CommandLineFailure(.usage, """
            The Security Extension can't run “Unrun”, so no event matches it. It names no type.
            """))
    }

    /// A Security Extension older than 3.1 has no indicators call and cuts the connection off at it: `--indicator`
    /// stops the stream before it starts, saying to update the Security Extension, and no stream is asked for.
    func testAnExtensionWithoutIndicatorsStopsTheStream() throws {
        let older = ServiceBeforeIndicators()
        var filter = StreamFilter()
        filter.indicators = ["Every exit"]
        let run = StreamCommandRun(harness: nil, endpoint: older.endpoint,
                                   formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                   filter: filter, indicatorTimeout: .seconds(1))
        var invocation = StreamInvocation()
        invocation.filter = filter
        run.start(invocation)
        XCTAssertTrue(waitUntil(timeout: 10) { !run.reported.isEmpty })
        XCTAssertEqual(run.reported, [.failed(.indicatorsUnanswered)])
        XCTAssertTrue(CommandLineFailure.indicatorsUnanswered.message.contains("Update the Security Extension"))
        XCTAssertEqual(older.streamRequests, 0)
    }

    /// `--indicator` matches a record's hit by its name, ignoring case, or its identity, in any case, and nothing
    /// else: not a name that's only a prefix, nor a record without indicators.
    func testTheFilterMatchesANameOrAnID() throws {
        let id = UUID()
        let record: NSDictionary = ["indicators": [["id": id.uuidString, "name": "Plist modified"]]]
        var filter = StreamFilter()
        for reference in ["plist MODIFIED", id.uuidString, id.uuidString.lowercased()] {
            filter.indicators = [reference]
            XCTAssertTrue(try filter.admits(record: record), reference)
        }
        for reference in ["Plist", UUID().uuidString, "not-a-uuid"] {
            filter.indicators = [reference]
            XCTAssertFalse(try filter.admits(record: record), reference)
        }
        filter.indicators = ["Plist modified"]
        XCTAssertFalse(try filter.admits(record: NSDictionary()))
    }

    /// The stream's encoders write the verdicts an event carries and match nothing themselves: an event without them
    /// has no `indicators` key. Given indicators, an encoder still matches those for an event without verdicts.
    func testEncodersWriteOnlyStoredVerdicts() throws {
        var message = try XCTUnwrap(SyntheticCorpus.records().first).message
        message.indicators = nil
        let plain = try jsonObject(StreamPipeline.Formatter.encoders(model: eventModel)[0].line(for: message))
        XCTAssertNil(plain["indicators"])
        var every = everyExit
        every.predicate = "event_type >= 0"
        let matched = try jsonObject(ExportEncoder(model: eventModel, indicators: [every]).line(for: message))
        XCTAssertEqual((matched["indicators"] as? [[String: Any]])?.first?["evaluated_by"] as? String, "export")

        message.indicators = IndicatorVerdicts([IndicatorHit(everyExit, isDefault: false,
                                                             evaluatedBy: .securityExtension)])
        let stamped = try jsonObject(ExportEncoder(model: eventModel).line(for: message))
        let hits = try XCTUnwrap(stamped["indicators"] as? [[String: Any]])
        XCTAssertEqual(hits.map { $0["id"] as? String }, [everyExit.id.uuidString])
        XCTAssertEqual(hits.first?["evaluated_by"] as? String, "security_extension")
        message.indicators = IndicatorVerdicts([])
        let none = try jsonObject(ExportEncoder(model: eventModel).line(for: message))
        XCTAssertEqual((none["indicators"] as? [Any])?.count, 0)
    }
}
