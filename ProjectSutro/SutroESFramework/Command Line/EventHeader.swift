//
//  EventHeader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Event header
/// The fields of a wire event (`Message` JSON) `macmonitor` reads before anything else: what drop accounting, pipeline
/// suppression, and a text line need.
///
/// Decoding only these is about four times cheaper than decoding a whole `Message` (21 µs against 90 µs an event),
/// which keeps text output fast. JSONL output decodes the `Message` anyway, and takes its header from it.
public struct EventHeader: Decodable, Equatable {
    /// The initiating process.
    public struct Process: Decodable, Equatable {
        /// Its process ID.
        public let pid: Int32
        /// Its process group.
        public let groupID: Int32
        /// Its effective user's name, such as "root".
        public let user: String?
        /// Its executable's path.
        public let path: String?
        
        private enum CodingKeys: String, CodingKey {
            case pid, group_id, euid_human, executable
        }
        
        private enum ExecutableKeys: String, CodingKey {
            case path
        }
        
        /// - Parameters:
        ///   - pid: The process ID.
        ///   - groupID: The process group.
        ///   - user: The effective user's name.
        ///   - path: The executable's path.
        public init(pid: Int32, groupID: Int32, user: String?, path: String?) {
            self.pid = pid
            self.groupID = groupID
            self.user = user
            self.path = path
        }
        
        /// Read `process` from a wire event.
        ///
        /// - Parameter decoder: The decoder.
        /// - Throws: A `DecodingError` for a missing `pid` or `group_id`.
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            pid = try container.decode(Int32.self, forKey: .pid)
            groupID = try container.decode(Int32.self, forKey: .group_id)
            user = try container.decodeIfPresent(String.self, forKey: .euid_human)
            /// Missing or `null` when Endpoint Security named no executable.
            let executable = try? container.nestedContainer(keyedBy: ExecutableKeys.self, forKey: .executable)
            path = try executable?.decodeIfPresent(String.self, forKey: .path)
        }
    }
    
    /// `seq_num`: per client and event type. Missing before message version 2.
    public let sequence: Int?
    /// `global_seq_num`: per client. Missing before message version 4.
    public let globalSequence: Int?
    /// `event_type`: the `es_event_type_t` raw value.
    public let eventType: Int
    /// `es_event_type`: the `ES_EVENT_TYPE_*` name.
    public let name: String
    /// `time`: when the event happened, in UTC, as eslogger writes it.
    public let time: String
    /// The initiating process.
    public let process: Process
    /// Mac Monitor's one-line summary of the event, such as an exec's command line.
    public let context: String?
    /// The path the event targets, if it has one.
    public let targetPath: String?
    
    private enum CodingKeys: String, CodingKey {
        case seq_num, global_seq_num, event_type, es_event_type, time, process, context, target_path
    }
    
    /// - Parameters:
    ///   - sequence: `seq_num`.
    ///   - globalSequence: `global_seq_num`.
    ///   - eventType: The `es_event_type_t` raw value.
    ///   - name: The `ES_EVENT_TYPE_*` name.
    ///   - time: The UTC time.
    ///   - process: The initiating process.
    ///   - context: The one-line summary.
    ///   - targetPath: The target path.
    public init(sequence: Int?, globalSequence: Int?, eventType: Int, name: String, time: String, process: Process,
                context: String?, targetPath: String?) {
        self.sequence = sequence
        self.globalSequence = globalSequence
        self.eventType = eventType
        self.name = name
        self.time = time
        self.process = process
        self.context = context
        self.targetPath = targetPath
    }
    
    /// The header of an event already decoded.
    ///
    /// - Parameter message: The event.
    public init(_ message: Message) {
        self.init(sequence: message.seq_num, globalSequence: message.global_seq_num, eventType: message.event_type,
                  name: message.es_event_type, time: message.time,
                  process: Process(pid: message.process.pid, groupID: message.process.group_id,
                                   user: message.process.euid_human, path: message.process.executable?.path),
                  context: message.context, targetPath: message.target_path)
    }
    
    /// Read the header of a wire event.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing `event_type`, `es_event_type`, `time`, or `process`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = try container.decodeIfPresent(Int.self, forKey: .seq_num)
        globalSequence = try container.decodeIfPresent(Int.self, forKey: .global_seq_num)
        eventType = try container.decode(Int.self, forKey: .event_type)
        name = try container.decode(String.self, forKey: .es_event_type)
        time = try container.decode(String.self, forKey: .time)
        process = try container.decode(Process.self, forKey: .process)
        context = try container.decodeIfPresent(String.self, forKey: .context)
        targetPath = try container.decodeIfPresent(String.self, forKey: .target_path)
    }
}
