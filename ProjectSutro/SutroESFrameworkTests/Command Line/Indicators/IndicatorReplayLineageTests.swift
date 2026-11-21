//
//  IndicatorReplayLineageTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Replaying lineage
/// Pins that a replay reads an event's ancestors from the trace alone, as `macmonitor indicators test` and the
/// indicators repository's CI do: from its forks, its execs and its process snapshots, in whatever order the trace
/// holds them. A snapshot is no event and has no verdicts.
final class IndicatorReplayLineageTests: XCTestCase {
    /// `macmonitor stream`'s JSONL for the capture with snapshots, in a file.
    ///
    /// - Parameters:
    ///   - filter: Which events the stream writes.
    ///   - reorder: Reorders the stream's lines.
    /// - Returns: The file.
    /// - Throws: If a fixture can't be read or the file can't be written.
    private func trace(_ filter: StreamFilter = StreamFilter(), exits: Bool = false,
                       reorder: ([Substring]) throws -> [Substring] = { $0 }) throws -> URL {
        let scope = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                  includeSelf: false)
        let stream = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: scope,
                                    forTerminal: false, filter: filter)
        let output = String(decoding: stream.process(try captureWithSnapshots(exits: exits)), as: UTF8.self)
        let lines = try reorder(output.split(separator: "\n"))
        return try temporaryFile(containing: lines.joined(separator: "\n") + "\n", named: "lineage.jsonl")
    }

    /// A trace's line with its JSON changed.
    ///
    /// - Parameters:
    ///   - line: The line.
    ///   - change: Changes the record.
    /// - Returns: The changed line.
    /// - Throws: If the line isn't a JSON object.
    private func rewriting(_ line: Substring, _ change: (inout [String: Any]) -> Void) throws -> Substring {
        var record = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        change(&record)
        let data = try JSONSerialization.data(withJSONObject: record, options: .withoutEscapingSlashes)
        return Substring(String(decoding: data, as: UTF8.self))
    }

    /// The lines an indicator matches in a trace.
    ///
    /// - Parameters:
    ///   - predicate: The indicator's predicate.
    ///   - url: The trace.
    /// - Returns: The lines matched, and how many records left it undetermined.
    /// - Throws: ``IndicatorReplay/Failure``.
    private func matches(_ predicate: String, in url: URL) throws -> (lines: [Int], undetermined: Int) {
        let indicator = ownIndicator("Lineage", predicate)
        var replay = IndicatorReplay([indicator])
        XCTAssertEqual(replay.compiled.problems.map(\.reason), [])
        var lines: [Int] = [], undetermined = 0
        try replay.replay(url) { verdicts in
            if verdicts.matched.contains(indicator.id) { lines.append(verdicts.line) }
            undetermined += verdicts.undetermined.count
        }
        return (lines, undetermined)
    }

    /// Both execs descend from sshd, which the trace knows only by its snapshot. The first exec's parent is the
    /// shell, another snapshot, and the second's is the first exec's program.
    func testAncestorsAreReadFromSnapshotsAndExecs() throws {
        let url = try trace()
        let sshd = #"event.exec != nil AND ANY lineage.paths ENDSWITH "/sshd""#
        XCTAssertEqual(try matches(sshd, in: url).lines, [4, 6])
        XCTAssertEqual(try matches(sshd, in: url).undetermined, 0)
        XCTAssertEqual(try matches(#"event.exec != nil AND lineage.parent.executable.path == "/bin/zsh""#, in: url).lines,
                       [4])
        XCTAssertEqual(try matches(#"event.exec != nil AND lineage.parent.executable.path == "/bin/sh""#, in: url).lines,
                       [6])
        XCTAssertEqual(try matches(#"event.exec != nil AND lineage.origin.executable.path == "/usr/sbin/sshd""#,
                                   in: url).lines, [4, 6])
        XCTAssertEqual(try matches(#"event.fork != nil AND lineage.parent.executable.path == "/usr/sbin/sshd""#,
                                   in: url).lines, [3], "A fork's lineage is the forking process's")
    }

    /// The trace is read whole before any record is evaluated, so its order doesn't matter: an exec ahead of the
    /// fork and the snapshots that explain it still has its ancestors.
    func testTheOrderOfATraceDoesNotMatter() throws {
        let url = try trace { Array($0.reversed()) }
        XCTAssertEqual(try matches(#"event.exec != nil AND ANY lineage.paths ENDSWITH "/sshd""#, in: url).lines,
                       [1, 3])
    }

    /// A stream of one process's events holds its ancestors as snapshots, one of them made from an exec the
    /// stream left out, and replays the same. Without its snapshots, the same record has no ancestors to match.
    func testAFilteredStreamReplaysTheSame() throws {
        var filter = StreamFilter()
        filter.pids = [300]
        let url = try trace(filter)
        let rule = #"event.exec != nil AND lineage.parent.executable.path == "/bin/sh" "#
            + #"AND ANY lineage.paths ENDSWITH "/sshd""#
        XCTAssertEqual(try matches(rule, in: url).lines, [4])
        let bare = try trace(filter) { $0.filter { !$0.contains("process_snapshot") } }
        XCTAssertEqual(try matches(rule, in: bare).lines, [])
    }

    /// An exec is stamped with the ancestors the Security Extension knew, which it took from the fork. The exec's
    /// parent token can say otherwise: launchd, once the process that forked it has exited, or a newer program,
    /// once that process has exec'd again. A stream that left the fork out replays by the stamped keys.
    func testAnExecReplaysByItsStampedAncestors() throws {
        var filter = StreamFilter()
        filter.pids = [300]
        let rule = #"event.exec != nil AND lineage.parent.executable.path == "/bin/sh" "#
            + #"AND ANY lineage.paths ENDSWITH "/sshd""#
        for (pid, pidversion) in [(1, 1), (200, 9)] {
            let url = try trace(filter) { lines in
                try lines.map { line in
                    guard !line.contains("process_snapshot") else { return line }
                    return try self.rewriting(line) { record in
                        var event = record["event"] as? [String: Any] ?? [:]
                        var exec = event["exec"] as? [String: Any] ?? [:]
                        var target = exec["target"] as? [String: Any] ?? [:]
                        var token = target["parent_audit_token"] as? [String: Any] ?? [:]
                        token["pid"] = pid
                        token["pidversion"] = pidversion
                        target["parent_audit_token"] = token
                        target["ppid"] = pid
                        exec["target"] = target
                        event["exec"] = exec
                        record["event"] = event
                    }
                }
            }
            XCTAssertEqual(try matches(rule, in: url).lines, [4], "Parent token \(pid).\(pidversion)")
        }
    }

    /// A process's key means one process only within one start of the Mac. A trace that holds two starts, with
    /// the same keys naming other programs, gives each record the ancestors of its own.
    func testEachBootSessionHasItsOwnAncestors() throws {
        let boots = ["0F1E2D3C-0000-4000-8000-00000000000A", "0F1E2D3C-0000-4000-8000-00000000000B"]
        let url = try trace { lines in
            try boots.enumerated().flatMap { index, boot in
                try lines.map { line in
                    let line = index == 0 ? line : Substring(line.replacingOccurrences(of: "/usr/sbin/sshd",
                                                                                       with: "/usr/sbin/cron"))
                    return try self.rewriting(line) { $0["boot_session_uuid"] = boot }
                }
            }
        }
        XCTAssertEqual(try matches(#"event.exec != nil AND ANY lineage.paths ENDSWITH "/sshd""#, in: url).lines,
                       [4, 6])
        XCTAssertEqual(try matches(#"event.exec != nil AND ANY lineage.paths ENDSWITH "/cron""#, in: url).lines,
                       [10, 12])
    }

    /// A stream of one event type that creates no process still replays: the record's own process and its
    /// ancestors are in the trace as snapshots. A fixture's snapshots have no Sensor ID, and read the same.
    func testAnEventThatCreatesNoProcessReplaysFromSnapshots() throws {
        var filter = StreamFilter()
        filter.predicates = [try StreamFilter.Predicate("event.exit != nil")]
        let rule = #"event.exit != nil AND lineage.parent.executable.path == "/bin/sh" "#
            + #"AND lineage.origin.executable.path == "/usr/sbin/sshd""#
        XCTAssertEqual(try matches(rule, in: try trace(filter, exits: true)).lines, [5])
        let scrubbed = try trace(filter, exits: true) { lines in
            lines.map { line in
                guard line.contains("process_snapshot"), let end = line.range(of: #","sensor_id":""#) else { return line }
                return line[..<end.lowerBound] + "}"
            }
        }
        XCTAssertEqual(try matches(rule, in: scrubbed).lines, [5])
    }

    /// File > Open Trace reads the events of a trace that has snapshots, and counts none of the snapshots as a
    /// record it couldn't read.
    func testOpenTraceReadsATraceWithSnapshots() throws {
        let store = CoreDataController(model: eventModel)
        let summary = try openTrace(try trace(), in: store)
        XCTAssertEqual(summary.skipped, 0)
        XCTAssertEqual(try storedMachTimes(in: store).count, 4)
    }
}
