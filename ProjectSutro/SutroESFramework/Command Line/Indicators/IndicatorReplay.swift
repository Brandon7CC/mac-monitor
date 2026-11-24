//
//  IndicatorReplay.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Replaying recorded events
/// Recorded events replayed through the Security Extension's own code: each record of a trace read as File > Open
/// Trace... reads it (``TraceImporter/message(from:)``), then evaluated by a ``CompiledIndicators`` made from the
/// indicators, as the Security Extension evaluates each event it captures. The verdicts a record carried when it was
/// captured are ignored: every verdict is fresh.
///
/// An indicator reads an event's ancestors from the trace itself: its forks, its execs and its process snapshots
/// (``TraceLineage``), read before the first record is evaluated. A snapshot isn't an event and has no verdicts.
///
/// Every indicator given is run, those that are off too, so a pack's indicator that ships off is tested like the
/// rest. Sequences run as the Security Extension runs them, with each record's own time, and each file starts with no
/// open chains, so one recording's steps never complete another's. Records are handed over in the file's order, as
/// lanes hand events over: an ordered step that comes in the file before the step it follows, as `macmonitor stream`
/// writes an app's held exec after the app's first file events, still completes the chain when its time follows, and
/// the record whose arrival completes it is the one tagged.
struct IndicatorReplay {
    /// One record's verdicts.
    struct Verdicts {
        /// The line, from 1, the record starts on.
        let line: Int
        /// The indicators it matched.
        let matched: Set<UUID>
        /// The indicators it left undetermined.
        let undetermined: Set<UUID>
    }

    /// Why a record or a file can't be replayed.
    enum Failure: Error, Equatable {
        /// The file can't be opened or read, and why.
        case unreadable(String)
        /// A record isn't an event Mac Monitor reads: its line, and why.
        case badRecord(line: Int, String)
    }

    /// The indicators, compiled as the Security Extension compiles them.
    let compiled: CompiledIndicators
    /// The values each event's rules read, kept between events as the Security Extension keeps them.
    private var values = MessageValueCache()

    /// - Parameter indicators: The indicators to run, each turned on.
    init(_ indicators: [Indicator]) {
        compiled = CompiledIndicators(indicators.map { indicator in
            var on = indicator
            on.isEnabled = true
            return on
        }, defaults: [:])
    }

    /// Replay a file's records, in its order.
    ///
    /// - Parameters:
    ///   - url: The file: JSONL, or any trace File > Open Trace... reads.
    ///   - each: Called with each record's verdicts.
    /// - Throws: ``Failure`` for a file that can't be read, or the first record that isn't an event.
    mutating func replay(_ url: URL, each: (Verdicts) -> Void) throws(Failure) {
        compiled.forgetChains()
        let reader: TraceRecordReader
        let lineages: TraceLineage.Tables
        /// What a record from a start of the Mac the trace says nothing of is read from: no ancestors.
        let unknown = ProcessLineage.replaying()
        do {
            lineages = try TraceLineage.tables(of: url)
            reader = try TraceRecordReader(url: url)
        } catch {
            throw .unreadable(error.localizedDescription)
        }
        while true {
            let record: TraceRecordReader.Record?
            do {
                record = try reader.next()
            } catch {
                throw .unreadable(error.localizedDescription)
            }
            switch record {
            case nil:
                return
            case .malformed(let line)?:
                throw .badRecord(line: line, "it isn't a JSON object")
            case .object(let data, _)? where TraceLineage.snapshot(in: data) != nil:
                continue
            case .object(let data, let line)?:
                let message: Message
                do {
                    message = try TraceImporter.message(from: data)
                } catch {
                    throw .badRecord(line: line, "it isn't an event Mac Monitor reads: \(error)")
                }
                values.lineage = lineages[message.boot_session_uuid] ?? unknown
                let evaluation = compiled.evaluate(message, values: &values)
                each(Verdicts(line: line, matched: Set(evaluation.hits.map(\.id)),
                              undetermined: Set(evaluation.undetermined.map(\.hit.id))))
            }
        }
    }
}
