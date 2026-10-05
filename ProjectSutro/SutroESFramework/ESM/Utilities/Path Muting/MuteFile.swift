//
//  MuteFile.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Limits
/// How much a mute file, or a request about the saved mute set, may hold.
public enum MuteLimits {
    /// The most bytes in a mute file or a request, checked before parsing: 1 MiB.
    public static let maxFileBytes: Int = 1 << 20
    /// The most mutes after merging by path and type.
    public static let maxMutes: Int = 4_096
    /// The longest path, in UTF-8 bytes (`PATH_MAX`).
    public static let maxPathBytes: Int = Int(PATH_MAX)
    /// The most event names in one mute, duplicates included: several times every event Endpoint Security has.
    public static let maxEventsPerMute: Int = 512
}


// MARK: - Mute file
/// Mac Monitor's mute file, format version 1: the saved mute set on disk, what Export writes and Import reads, and
/// the entries requests about the saved set carry.
///
/// ```json
/// {
///   "mutes" : [
///     { "events" : [], "path" : "/usr/libexec/logd", "type" : "ES_MUTE_PATH_TYPE_LITERAL" }
///   ],
///   "version" : 1
/// }
/// ```
///
/// Types and events use their Endpoint Security names, and no events (or none listed) means every event. `PREFIX`
/// and `LITERAL` match the process, `TARGET_PREFIX` and `TARGET_LITERAL` the target. Unknown keys are ignored, so a
/// later version can add fields; a change in meaning bumps ``version``.
public struct MuteFile: Codable, Equatable, Sendable {
    /// The format version this Mac Monitor writes and reads.
    public static let currentVersion: Int = 1
    /// The file's format version.
    public var version: Int
    /// The mutes, one per path and type when the file is canonical.
    public var mutes: [Entry]
    
    private enum CodingKeys: String, CodingKey {
        case version, mutes
    }
    
    /// - Parameters:
    ///   - version: The format version.
    ///   - mutes: The entries.
    public init(version: Int = MuteFile.currentVersion, mutes: [Entry]) {
        self.version = version
        self.mutes = mutes
    }
    
    /// A list's file, in canonical order: by type name then path, each entry's events by name.
    ///
    /// - Parameter list: The list.
    public init(_ list: MuteList) {
        self.init(mutes: list.mutes.map(Entry.init))
    }
    
    /// Read the version first, so a newer file is reported as such rather than as malformed.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: ``MuteFileError/unsupportedVersion(_:)`` past ``currentVersion``, ``MuteFileError/malformed(_:)``
    ///   below 1, or a `DecodingError`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        guard version >= 1 else { throw MuteFileError.malformed("“version” is \(version)") }
        guard version <= Self.currentVersion else { throw MuteFileError.unsupportedVersion(version) }
        mutes = try container.decode([Entry].self, forKey: .mutes)
    }
    
    /// The file's bytes: pretty printed with sorted keys and unescaped slashes, plus a final newline. The same
    /// file always gives the same bytes, so `macmonitor mute export` prints exactly the saved file.
    ///
    /// - Returns: The JSON.
    public func encoded() -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        /// Only strings and integers: encoding can't fail.
        let json = (try? encoder.encode(self)) ?? Data()
        return json + Data("\n".utf8)
    }
    
    /// Read a version 1 file, structure only (see ``list(_:)`` for its mutes).
    ///
    /// - Parameter data: The file's bytes.
    /// - Returns: The file.
    /// - Throws: ``MuteFileError``: too large (checked before parsing), a newer version, or malformed.
    public static func decode(_ data: Data) throws -> MuteFile {
        guard data.count <= MuteLimits.maxFileBytes else { throw MuteFileError.tooLarge(bytes: data.count) }
        do {
            return try JSONDecoder().decode(MuteFile.self, from: data)
        } catch let error as MuteFileError {
            throw error
        } catch {
            throw MuteFileError.malformed(reason(error))
        }
    }
    
    /// A decoding failure in a few words.
    ///
    /// - Parameter error: The error `JSONDecoder` threw.
    /// - Returns: What's wrong, such as "“mutes.2.path” is missing".
    static func reason(_ error: Error) -> String {
        /// Where in the file, such as "mutes.2.path".
        func location(_ context: DecodingError.Context, _ key: CodingKey? = nil) -> String {
            (context.codingPath + [key].compactMap { $0 }).map { $0.intValue.map(String.init) ?? $0.stringValue }
                .joined(separator: ".")
        }
        switch error as? DecodingError {
        case .keyNotFound(let key, let context)?:
            return "“\(location(context, key))” is missing"
        case .typeMismatch(_, let context)? where context.codingPath.isEmpty:
            return "it isn't a JSON object with “version” and “mutes”"
        case .typeMismatch(_, let context)?, .valueNotFound(_, let context)?:
            return "“\(location(context))” has the wrong type"
        case .dataCorrupted?:
            return "it isn't valid JSON"
        default:
            return error.localizedDescription
        }
    }
}


// MARK: - Entries
extension MuteFile {
    /// One mute: a path, how it's matched, and its events.
    public struct Entry: Codable, Hashable, Sendable {
        /// The path, or path prefix, to match.
        public var path: String
        /// The `ES_MUTE_PATH_TYPE_*` name.
        public var type: String
        /// `ES_EVENT_TYPE_*` names. Empty means every event.
        public var events: [String]
        
        private enum CodingKeys: String, CodingKey {
            case path, type, events
        }
        
        /// - Parameters:
        ///   - path: The path, or path prefix, to match.
        ///   - type: The `ES_MUTE_PATH_TYPE_*` name.
        ///   - events: `ES_EVENT_TYPE_*` names. Empty means every event.
        public init(path: String, type: String, events: [String] = []) {
            self.path = path
            self.type = type
            self.events = events
        }
        
        /// A mute's entry, by Endpoint Security's names.
        ///
        /// - Parameter mute: The mute.
        public init(_ mute: PathMute) {
            self.init(path: mute.path, type: getMuteCaseString(muteType: mute.type),
                      events: mute.events.map { eventTypeToString(from: $0) })
        }
        
        /// Missing events mean every event, as an empty list does.
        ///
        /// - Parameter decoder: The decoder.
        /// - Throws: A `DecodingError` for a missing path or type, or a value of the wrong type.
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            path = try container.decode(String.self, forKey: .path)
            type = try container.decode(String.self, forKey: .type)
            events = try container.decodeIfPresent([String].self, forKey: .events) ?? []
        }
        
        /// Names the entry in messages: its path and type.
        public var label: String { "“\(path)” (\(type))" }
    }
}


// MARK: - Errors
/// Why a mute file, or the mutes of a request, can't be read.
public enum MuteFileError: Error, Equatable, CustomStringConvertible {
    /// Over ``MuteLimits/maxFileBytes``.
    case tooLarge(bytes: Int)
    /// Over ``MuteLimits/maxMutes`` once merged by path and type.
    case tooManyMutes(Int)
    /// A format version past ``MuteFile/currentVersion``: written by a newer Mac Monitor.
    case unsupportedVersion(Int)
    /// Not a mute file, or not JSON.
    case malformed(String)
    /// A mute that can't be used, by its position (from 0).
    case invalidMute(index: Int, reason: String)
    /// A line of a list exported before 2.2 that isn't a muted path, by its number (from 1).
    case invalidLine(line: Int, reason: String)
    
    /// The problem, as a sentence for Mac Monitor and `macmonitor` to show.
    public var description: String {
        switch self {
        case .tooLarge(let bytes):
            return "The file is \(bytes) bytes. A mute file can be at most 1 MiB (\(MuteLimits.maxFileBytes) bytes)."
        case .tooManyMutes(let count):
            return "It has \(count) mutes. The saved mute set can hold at most \(MuteLimits.maxMutes)."
        case .unsupportedVersion(let version):
            return """
                It's mute file version \(version), written by a newer Mac Monitor. This one reads version \
                \(MuteFile.currentVersion).
                """
        case .malformed(let reason):
            return "It isn't a Mac Monitor mute file: \(reason)."
        case .invalidMute(let index, let reason):
            return "Mute \(index + 1) can't be used: \(reason)."
        case .invalidLine(let line, let reason):
            return "Line \(line) isn't a muted path: \(reason)."
        }
    }
}
