//
//  MuteFileReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Import
/// What a mute file holds, ready to replace or add to the saved set.
public struct MuteImport: Sendable {
    /// How the file was written.
    public enum Format: Sendable {
        /// A ``MuteFile``, as Mac Monitor 2.2 and later export.
        case current
        /// One `ESMutedPath` JSON object per line, as Mac Monitor exported before 2.2.
        case legacy
    }
    
    /// How the file was written.
    public let format: Format
    /// The mutes it holds, merged by path and type.
    public let list: MuteList
    /// Entries left out and events dropped, as sentences to show before importing.
    public let warnings: [String]
}


// MARK: - Reader
/// Reads a mute file for Import (Mac Monitor and `macmonitor`), whichever way it was written.
///
/// Import is lenient and visible: an entry that can't be used is left out, and each thing left out comes back as a
/// warning to show before anything is sent. The Security Extension is strict: it refuses any request with an entry it
/// can't use, and never reads a file itself.
public enum MuteFileReader {
    /// One line of a list exported before 2.2: an `ESMutedPath`, of which only these keys matter (`eventCount` and
    /// `id` are ignored).
    private struct Line: Decodable {
        let path: String
        let type: String
        let events: [String]?
    }
    
    /// Read a version 1 mute file, or the list Mac Monitor exported before 2.2 (one `ESMutedPath` JSON object per
    /// line, such as Export ▸ Current mute set… and the files in "Mute sets/").
    ///
    /// The version 1 reader goes first. If both fail, the error shown is the legacy one only when the first line reads
    /// as a legacy entry.
    ///
    /// - Parameter data: The file's bytes.
    /// - Returns: The mutes, how the file was written, and what was left out.
    /// - Throws: ``MuteFileError``.
    public static func read(_ data: Data) throws -> MuteImport {
        guard data.count <= MuteLimits.maxFileBytes else { throw MuteFileError.tooLarge(bytes: data.count) }
        let lines = Self.lines(of: data)
        guard !lines.isEmpty else { throw MuteFileError.malformed("the file is empty") }
        let file: MuteFile
        do {
            file = try MuteFile.decode(data)
        } catch let currentError {
            do {
                let entries = try legacyEntries(lines)
                let (list, warnings) = try MuteFile.list(from: entries, .lenient)
                return MuteImport(format: .legacy, list: list, warnings: warnings)
            } catch let legacyError {
                guard (try? line(lines[0].text)) != nil else { throw currentError }
                throw legacyError
            }
        }
        let (list, warnings) = try file.list(.lenient)
        return MuteImport(format: .current, list: list, warnings: warnings)
    }
    
    /// The file's non-blank lines with their numbers (from 1). LF and CRLF both end a line.
    ///
    /// - Parameter data: The file's bytes.
    /// - Returns: The lines, trimmed.
    private static func lines(of data: Data) -> [(number: Int, text: String)] {
        String(decoding: data, as: UTF8.self).split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
            .enumerated()
            .map { (number: $0.offset + 1, text: $0.element.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.text.isEmpty }
    }
    
    /// Read one legacy line.
    ///
    /// - Parameter text: The line.
    /// - Returns: The muted path it describes.
    /// - Throws: A `DecodingError`.
    private static func line(_ text: String) throws -> Line {
        try JSONDecoder().decode(Line.self, from: Data(text.utf8))
    }
    
    /// Every legacy line as an entry.
    ///
    /// Endpoint Security lists a path muted for every event with every event type it has, AUTH events included, so an
    /// entry naming every NOTIFY event Mac Monitor can capture (and, for a target type, every one that can be muted by
    /// target path) reads as every event: it can't mute anything more for Mac Monitor.
    ///
    /// - Parameter lines: The non-blank lines.
    /// - Returns: The entries.
    /// - Throws: ``MuteFileError/invalidLine(line:reason:)`` for a line that isn't JSON or lacks a path or type.
    private static func legacyEntries(_ lines: [(number: Int, text: String)]) throws -> [MuteFile.Entry] {
        var entries: [MuteFile.Entry] = []
        for (number, text) in lines {
            let line: Line
            do {
                line = try Self.line(text)
            } catch {
                throw MuteFileError.invalidLine(line: number, reason: MuteFile.reason(error))
            }
            var entry = MuteFile.Entry(path: line.path, type: line.type, events: line.events ?? [])
            let named = Set(entry.events.map { eventStringToType(from: $0) })
            if named.isSuperset(of: everyEvent(for: entry.muteType)) { entry.events = [] }
            entries.append(entry)
        }
        return entries
    }
    
    /// Every event a mute of this type can cover for Mac Monitor.
    ///
    /// - Parameter type: The mute type, if it's known.
    /// - Returns: Every NOTIFY event Mac Monitor captures, or for a target type those that can be muted by target path.
    static func everyEvent(for type: es_mute_path_type_t?) -> Set<es_event_type_t> {
        let captured = Set(supportedEvents)
        guard type == ES_MUTE_PATH_TYPE_TARGET_PREFIX || type == ES_MUTE_PATH_TYPE_TARGET_LITERAL else {
            return captured
        }
        return captured.intersection(allowedTargetPathEvents)
    }
}
