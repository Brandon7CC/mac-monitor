//
//  TraceRecordReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Record reader
/// Splits a trace into its JSON objects, reading the file a chunk at a time, and numbers the lines they start on.
///
/// A byte scanner that tracks strings (and their escapes) and object and array nesting, so it finds each top-level object
/// whatever separates them: newlines (JSONL), "\n" between pretty-printed objects, or the brackets and commas of a JSON
/// array. Text before an object on the object's own line is a prefix, such as the timestamp and process that `log show`
/// writes before each message, and is dropped; a line of text without an object is a malformed record.
///
/// A record cut short is skipped as soon as the next one starts, so one bad line doesn't swallow the rest of the file:
/// a raw newline can't occur inside a JSON string, and a `{` at the start of a line only starts an event (JSONL lines and
/// pretty events written by any JSON encoder start there; their nested objects are indented). The exception is an
/// element of an array inside a JSON array file, which an encoder that doesn't indent (Python's `indent=0`) also starts
/// at the start of a line. A file whose first object follows text on its line is a text log: each object is on one line
/// (a message the unified log cut at its size limit ends with its line), so a newline also ends a record.
///
/// Only the bytes the file had when it was opened are read, so a file still being written ends where it ended then.
final class TraceRecordReader {
    /// A top-level JSON object, or text that isn't one, with the line it starts on (from 1).
    enum Record {
        /// A complete object: its bytes.
        case object(Data, line: Int)
        /// An object cut short, or a line of text without one.
        case malformed(line: Int)
    }
    
    /// Bytes read at a time.
    static let chunkSize = 1 << 20
    /// The longest record kept, strings included: an Endpoint Security event is at most a few megabytes, even
    /// pretty-printed. Anything longer is corrupt; it's skipped up to the next line starting with `{`.
    static let maxRecordSize = 32 << 20
    /// The bytes the scanner looks for.
    private static let (openBrace, closeBrace, openBracket, closeBracket, quote, backslash, comma, newline) =
        (UInt8(ascii: "{"), UInt8(ascii: "}"), UInt8(ascii: "["), UInt8(ascii: "]"), UInt8(ascii: "\""), UInt8(ascii: "\\"),
         UInt8(ascii: ","), UInt8(ascii: "\n"))
    
    /// The file's size when it was opened: where reading stops.
    let totalBytes: Int64
    /// The trace, open for reading.
    private let handle: FileHandle
    /// The most bytes to read.
    private let limit: Int64
    /// The chunks read and not yet scanned past, from the start of the record being scanned.
    private var buffer: [UInt8] = []
    /// Where scanning resumes in `buffer`, and where the record being scanned starts.
    private var position = 0, start: Int?
    /// The objects and arrays open in the record being scanned, innermost last: `true` for an array. Empty between
    /// records.
    private var containers: [Bool] = []
    /// The scanner's state: inside a string, after a backslash in one, and at the start of a line.
    private var inString = false, escaped = false, atLineStart = true
    /// The last byte of the record scanned that isn't whitespace or inside a string (a string's is its quote).
    private var lastSignificant: UInt8 = 0
    /// Bytes that are neither whitespace nor an array's brackets and commas seen since the last record, on this line.
    private var garbage = false
    /// Skipping an oversized record.
    private var skipping = false
    /// Is the file a text log, whose records end with their line? Decided by whether text comes before its first object.
    private var textLog: Bool?
    /// Has a `[` been seen between records, so the records are elements of a JSON array?
    private var arrayFile = false
    /// The line being scanned, and the line the record (or the text that isn't one) being scanned starts on.
    private var line = 1, recordLine = 1
    /// Bytes read from the file, and whether it has ended.
    private var consumed: Int64 = 0, finished = false
    
    /// Bytes of the file scanned so far.
    var bytesRead: Int64 { consumed - Int64(buffer.count - position) }
    
    /// - Parameters:
    ///   - url: The trace.
    ///   - limit: The most bytes to read: the file is taken to end there.
    /// - Throws: ``TraceImporter/Failure/notAFile`` for a folder, named pipe, or device (which could block reading
    ///   forever), or the error opening the file.
    init(url: URL, limit: Int64 = .max) throws {
        var info = stat()
        if stat(url.path, &info) == 0, info.st_mode & S_IFMT != S_IFREG { throw TraceImporter.Failure.notAFile }
        handle = try FileHandle(forReadingFrom: url)
        totalBytes = Int64((try? handle.seekToEnd()) ?? 0)
        try handle.seek(toOffset: 0)
        self.limit = min(limit, totalBytes)
    }
    
    /// Close the file.
    deinit { try? handle.close() }
    
    /// The next record.
    ///
    /// - Returns: The record, or `nil` at the end of the file.
    /// - Throws: A read error.
    func next() throws -> Record? {
        while true {
            if let record = scan() { return record }
            guard !finished else {
                /// The file ends inside a record, or after something that isn't one.
                defer { garbage = false; skipping = false }
                return start != nil || garbage ? abandon() : nil
            }
            try fill()
        }
    }
    
    /// Drop what's been scanned (keeping a record in progress) and read the next chunk.
    private func fill() throws {
        let keep = start ?? position
        buffer.removeSubrange(0..<keep)
        position -= keep
        start = start.map { $0 - keep }
        /// Give back the memory an oversized record took.
        if buffer.capacity > 4 * Self.chunkSize, buffer.count < Self.chunkSize { buffer = Array(buffer) }
        let count = Int(min(Int64(Self.chunkSize), limit - consumed))
        let chunk = count > 0 ? try autoreleasepool { try handle.read(upToCount: count) } ?? Data() : Data()
        /// A UTF-8 byte order mark isn't JSON.
        if consumed == 0, chunk.starts(with: [0xEF, 0xBB, 0xBF]) { buffer.append(contentsOf: chunk.dropFirst(3)) }
        else { buffer.append(contentsOf: chunk) }
        consumed += Int64(chunk.count)
        finished = chunk.isEmpty
    }
    
    /// Scan `buffer` from `position` to the end of the next record.
    ///
    /// - Returns: The record, or `nil` if the buffer ran out first.
    private func scan() -> Record? {
        buffer.withUnsafeBufferPointer { bytes -> Record? in
            while position < bytes.count {
                let byte = bytes[position], lineStart = atLineStart
                position += 1
                atLineStart = byte == Self.newline
                if atLineStart { line += 1 }
                if skipping {
                    guard lineStart && byte == Self.openBrace else { continue }
                    skipping = false
                    position -= 1
                    atLineStart = true
                    continue
                }
                if let first = start, position - first > Self.maxRecordSize {
                    skipping = true
                    return abandon()
                }
                if inString {
                    /// Escaped or not: the line ends the record.
                    if byte == Self.newline { return abandon() }
                    if escaped { escaped = false }
                    else if byte == Self.backslash { escaped = true }
                    else if byte == Self.quote { inString = false }
                    continue
                }
                guard let first = start else {
                    let blank = byte == 0x20 || byte == 0x09 || byte == 0x0D || byte == Self.newline
                    if byte == Self.openBrace {
                        start = position - 1
                        containers.append(false)
                        lastSignificant = byte
                        recordLine = line
                        /// What came before on the line is the object's prefix.
                        if textLog == nil { textLog = garbage }
                        garbage = false
                    } else if byte == Self.newline && garbage {
                        garbage = false
                        return .malformed(line: recordLine)
                    } else if byte == Self.openBracket && !garbage {
                        arrayFile = true
                    } else if !blank && byte != Self.openBracket && byte != Self.closeBracket && byte != Self.comma && !garbage {
                        garbage = true
                        recordLine = line
                    }
                    continue
                }
                switch byte {
                case Self.quote: inString = true
                case Self.openBrace where lineStart && !continuesArray: return restart()
                case Self.newline where textLog == true: return abandon()
                case Self.openBrace: containers.append(false)
                case Self.openBracket: containers.append(true)
                case Self.closeBrace, Self.closeBracket:
                    containers.removeLast()
                    if containers.isEmpty {
                        start = nil
                        return .object(Data(UnsafeBufferPointer(rebasing: bytes[first..<position])), line: recordLine)
                    }
                case 0x20, 0x09, 0x0D, Self.newline: continue
                default: break
                }
                lastSignificant = byte
            }
            return nil
        }
    }
    
    /// Does a `{` at the start of a line continue the record, as the next element of an array in a JSON array file?
    private var continuesArray: Bool {
        arrayFile && containers.last == true && (lastSignificant == Self.openBracket || lastSignificant == Self.comma)
    }
    
    /// Give up on the record in progress.
    ///
    /// - Returns: The malformed record.
    private func abandon() -> Record {
        start = nil
        containers.removeAll(keepingCapacity: true)
        inString = false
        escaped = false
        return .malformed(line: recordLine)
    }
    
    /// Give up on the record in progress because a new one starts at the `{` just scanned, which is scanned again.
    ///
    /// - Returns: The malformed record.
    private func restart() -> Record {
        position -= 1
        atLineStart = true
        return abandon()
    }
}
