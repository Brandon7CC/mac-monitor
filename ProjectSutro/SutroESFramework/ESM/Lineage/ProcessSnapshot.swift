//
//  ProcessSnapshot.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Process snapshot
/// A process a trace has no exec of, as its own line in the trace: one that was running before the capture started.
///
/// An exec or a fork names the ancestors of the process it creates by their keys (`ancestor_keys`). An ancestor
/// that started during the capture has its own exec in the trace, which says what it is. One that started before
/// has none, so the first record to name it is preceded by its snapshot: its program, and its own ancestors' keys.
/// Replay, Mac Monitor and search rebuild a process's ancestors from the execs, the forks and the snapshots
/// (``ProcessLineage/describe(_:ancestors:)``).
///
/// It isn't an event: it has no time, and nothing subscribes to it.
public struct ProcessSnapshot: Codable, Equatable, Sendable {
    /// A process's executable, as far as a snapshot says.
    public struct Executable: Codable, Equatable, Sendable {
        /// Its path.
        public var path: String
    }

    /// The process's key: its pid and pid version, as `ancestor_keys` names it.
    public var key: String
    /// Its ancestors' keys, nearest first, as an exec's are.
    public var ancestor_keys: [String]
    /// Its executable. `nil` when the process was gone before it could be read.
    public var executable: Executable?
    /// Its command line.
    public var command_line: String?
    /// Its signing ID. `nil` for unsigned code, and for a process whose signature was never read.
    public var signing_id: String?
    /// Its team ID.
    public var team_id: String?
    /// How it's signed, as a process's `codesigning_type` says it.
    public var codesigning_type: String?

    /// - Parameters:
    ///   - program: The process's program, from the lineage table.
    ///   - ancestors: Its ancestors' keys, nearest first.
    public init(_ program: ProcessProgram, ancestors: [ProcessKey]) {
        key = program.key.description
        ancestor_keys = ancestors.map(\.description)
        executable = program.path.map(Executable.init)
        command_line = program.commandLine
        signing_id = program.signingID
        team_id = program.teamID
        codesigning_type = program.codesigningType
    }

    /// The program it describes, for the lineage table. `nil` when its key isn't one.
    public var program: ProcessProgram? {
        ProcessKey(key).map {
            ProcessProgram(key: $0, path: executable?.path, commandLine: command_line, signingID: signing_id,
                           teamID: team_id, codesigningType: codesigning_type)
        }
    }

    /// Its ancestors' keys, for the lineage table. One that isn't a key is left out.
    public var ancestors: [ProcessKey] {
        ancestor_keys.compactMap { ProcessKey($0) }
    }
}


// MARK: - Its line
/// A process snapshot's line in a trace and on the wire: the snapshot, and the Sensor ID of the Mac it's from, as
/// every event carries.
public struct ProcessSnapshotRecord: Codable, Equatable, Sendable {
    /// The snapshot.
    public var process_snapshot: ProcessSnapshot
    /// The Sensor ID of the Mac it's from. `nil` in a test fixture, which has every Sensor ID removed.
    public var sensor_id: String?
    /// Which start of that Mac it's from (``BootSession``), as the records beside it say. `nil` when they don't.
    public var boot_session_uuid: String?

    /// How its line starts: `process_snapshot` is written first.
    private static let prefix = Data(#"{"process_snapshot":"#.utf8)
    /// Writes a line's keys in order, so every snapshot line starts the same way.
    private static let encoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()

    /// - Parameters:
    ///   - snapshot: The snapshot.
    ///   - sensorID: The Sensor ID of the Mac it's from, if it's known.
    ///   - bootSession: Which start of that Mac it's from, if it's known.
    public init(_ snapshot: ProcessSnapshot, sensorID: String?, bootSession: String? = nil) {
        process_snapshot = snapshot
        sensor_id = sensorID
        boot_session_uuid = bootSession
    }

    /// Is a line on the wire a snapshot's, not an event's? By how it starts, so an event isn't decoded to tell.
    ///
    /// - Parameter line: The line, as ``line`` writes one.
    /// - Returns: Whether it's a snapshot's.
    public static func isSnapshot(_ line: Data) -> Bool {
        line.starts(with: prefix)
    }

    /// Its line, with no newline: `process_snapshot` first, which is how a line is told from an event's, then
    /// where it's from. `nil` when it can't be encoded, which no snapshot is expected to cause.
    public var line: Data? {
        guard var line = try? Self.encoder.encode(process_snapshot) else { return nil }
        line.insert(contentsOf: Self.prefix, at: 0)
        for (key, value) in [("boot_session_uuid", boot_session_uuid), ("sensor_id", sensor_id)] {
            guard let value, let text = try? Self.encoder.encode(value) else { continue }
            line.append(contentsOf: Data(",\"\(key)\":".utf8) + text)
        }
        line.append(UInt8(ascii: "}"))
        return line
    }

    /// Read a snapshot's line.
    ///
    /// - Parameter line: The line.
    /// - Returns: The record, or `nil` when the line isn't one.
    public static func read(_ line: Data) -> ProcessSnapshotRecord? {
        try? JSONDecoder().decode(ProcessSnapshotRecord.self, from: line)
    }
}
