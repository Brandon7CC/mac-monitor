//
//  RCProcessHelpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//

import Foundation
import OSLog


public class ProcessHelpers {
    // MARK: Supported scripting interpreters
    /// Is `executableName` a supported scripting interpreter (``ScriptInterpreter/named(_:)``)?
    ///
    /// - Parameter executableName: The executable's file name.
    /// - Returns: Whether to look for the script among the exec's arguments.
    static func isScriptingInterpreter(_ executableName: String) -> Bool {
        ScriptInterpreter.named(executableName) != nil
    }
    
    
    // MARK: - Parsing the arguments of exec events
    /// An exec's arguments, in order.
    ///
    /// - Parameter execEvent: The exec event.
    /// - Returns: Each argument, or "" for one that isn't UTF-8.
    static func parseExecArgs(execEvent: inout es_event_exec_t) -> [String] {
        (0..<es_exec_arg_count(&execEvent)).map { es_exec_arg(&execEvent, $0).string ?? "" }
    }
    
    // MARK: - Parsing the environment variables of exec events
    /// An exec's environment variables, in order.
    ///
    /// - Parameter event: The exec event.
    /// - Returns: Each `NAME=value`, or "" for one that isn't UTF-8.
    public static func parseExecEnv(event: inout es_event_exec_t) -> [String] {
        (0..<es_exec_env_count(&event)).map { es_exec_env(&event, $0).string ?? "" }
    }
    
    // MARK: - Parsing the open file descriptors of exec events
    /// The file descriptors an exec's image starts with, in order.
    ///
    /// - Parameter event: The exec event.
    /// - Returns: Each file descriptor.
    public static func getFds(event: inout es_event_exec_t) -> [FileDescriptor] {
        (0..<es_exec_fd_count(&event)).map { FileDescriptor(from: es_exec_fd(&event, $0).pointee) }
    }
    
    // MARK: - Address to hex
    /// An address in lowercase hex, for example `0x104b9c000`.
    ///
    /// It used to take the address's decimal digits as a `String`, which `%llx` can't format: it printed the string's
    /// pointer instead, a different wrong value on every run.
    ///
    /// - Parameter address: The address.
    /// - Returns: `0x` and the address's hex digits.
    public static func toHex(_ address: UInt64) -> String {
        return String(format: "0x%llx", address)
    }
    
    // MARK: - Normalized size
    public static func sizeFromHexNormalized(size: Double) -> Int {
        let kb = Double(size) / 1024.0
        return Int(kb)
    }
    
    // MARK: - Event to JSON
    /// A value as JSON with sorted keys and unescaped slashes, as exports, the JSON tab and Copy JSON write events.
    ///
    /// - Parameters:
    ///   - value: The value, such as an `ESMessage`.
    ///   - pretty: Pretty-print it, rather than write it on one line.
    /// - Returns: The JSON, or `{}` if the value can't be encoded.
    public static func eventToJSON(value: Encodable, pretty: Bool = false) -> String {
        guard let encodedData = try? eventJSON(value, pretty: pretty) else { return "{}" }
        return String(data: encodedData, encoding: .utf8) ?? ""
    }
    
    /// The same JSON as ``eventToJSON(value:pretty:)``, as bytes, or the encoder's error.
    ///
    /// - Parameters:
    ///   - value: The value, such as an `ESMessage`.
    ///   - pretty: Pretty-print it, rather than write it on one line.
    /// - Returns: The JSON.
    /// - Throws: Why the value can't be encoded.
    static func eventJSON(_ value: Encodable, pretty: Bool) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            : [.withoutEscapingSlashes, .sortedKeys]
        return try encoder.encode(value)
    }
    
    // MARK: - Add to when supporting new ES events (if it has a process struct)
    /// The name of the process an event is about: a fork's child, an exec's target, or else the event's process.
    ///
    /// - Parameter message: The event.
    /// - Returns: The executable's name, "" for a fork child without one, or `EVENTS_CLEARED` when the event's process
    ///   has none either.
    public static func getTargetProcessName(message: ESMessage) -> String {
        if let fork = message.event.fork { return fork.child.executable?.name ?? "" }
        return message.event.exec?.target.executable?.name ?? message.process.executable?.name ?? "EVENTS_CLEARED"
    }
    
    // MARK: - Process event helper functions
    /// A `timespec` as a date.
    ///
    /// - Parameter timespec: Seconds and nanoseconds since 1970.
    /// - Returns: The date.
    public static func timespecToTimestamp(timespec: timespec) -> Date {
        Date(timeIntervalSince1970: Double(timespec.tv_sec) + Double(timespec.tv_nsec) / 1e9)
    }
    
    /// Formats event timestamps as `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'`.
    ///
    /// Shared rather than created per call: `Message.init` runs for every event in the Security Extension.
    /// `DateFormatter` is thread safe on macOS 10.9+ (see `NSDateFormatter.h`).
    static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter
    }()
    
    // MARK: - Reading scripts and plists
    /// The most bytes ``getFileContents(at:)`` reads: a longer script or plist is cut there.
    static let fileContentsLimit = 1 << 20
    
    /// The UTF-8 text of a regular file, such as a launch item's plist, up to ``fileContentsLimit``.
    ///
    /// - Parameter path: The file's path, or a `file://` URL's.
    /// - Returns: The text, cut at the limit back to the end of a whole character, or `nil` if the file isn't UTF-8
    ///   text or isn't a regular file (``openRegularFile(at:for:expecting:)``).
    public static func getFileContents(at path: String) -> String? {
        readRegularFile(at: path).flatMap(limitedText(of:))
    }

    /// The bytes of a regular file, up to one more than ``fileContentsLimit``, so a caller can tell a file that's cut.
    ///
    /// - Parameters:
    ///   - path: The file's path, or a `file://` URL's.
    ///   - reader: Who the file is read for, or `nil` for Mac Monitor itself.
    ///   - identity: The file the path must still name, or `nil` for any.
    /// - Returns: The bytes, or `nil` if ``openRegularFile(at:for:expecting:)`` doesn't open the file, or it can't be
    ///   read.
    static func readRegularFile(at path: String, for reader: FileReader? = nil,
                                expecting identity: FileIdentity? = nil) -> Data? {
        guard let file = openRegularFile(at: path, for: reader, expecting: identity) else { return nil }
        return try? file.read(upToCount: fileContentsLimit + 1) ?? Data()
    }

    /// Bytes as UTF-8 text, up to ``fileContentsLimit``.
    ///
    /// - Parameter data: The bytes.
    /// - Returns: The text, cut at the limit back to the end of a whole character, or `nil` if it isn't UTF-8.
    static func limitedText(of data: Data) -> String? {
        guard data.count > fileContentsLimit else { return String(data: data, encoding: .utf8) }
        /// A UTF-8 character is at most 4 bytes, so one of the last 4 cuts ends on a whole one.
        for end in stride(from: fileContentsLimit, to: fileContentsLimit - 4, by: -1) {
            if let text = String(data: data.prefix(end), encoding: .utf8) { return text }
        }
        return nil
    }
    
    /// Open a file for reading, only if it's a regular file, without waiting.
    ///
    /// An exec's arguments can name anything. Opening a FIFO that has no writer waits until something opens it for
    /// writing, and the capture lane building the event waited with it. Opening a device can have side effects. So the
    /// path is `stat`ed first, opened with `O_NONBLOCK`, and checked again with `fstat` in case it was replaced in
    /// between. A reader and an identity are checked on that `fstat` of the open file too, so a file swapped in after
    /// the checks is never the one read.
    ///
    /// - Parameters:
    ///   - path: The file's path, or a `file://` URL's. A symbolic link is followed.
    ///   - reader: Who the file is read for: it's refused unless they could read it themselves
    ///     (``FileReader/canRead(_:of:)``). `nil` reads it as Mac Monitor.
    ///   - identity: The file the path must still name (``FileIdentity``), or `nil` for any.
    /// - Returns: The open file, closed when it's released, or `nil` if the path doesn't name a regular file, it can't
    ///   be opened, or the reader or identity refuses it.
    static func openRegularFile(at path: String, for reader: FileReader? = nil,
                                expecting identity: FileIdentity? = nil) -> FileHandle? {
        let path = path.droppingPrefix("file://")
        var info = stat()
        guard stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG, identity?.matches(info) ?? true,
              reader?.canRead(info, of: descriptor) ?? true else { return nil }
        return file
    }
}
