//
//  RCProcessHelpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//

import Foundation
import OSLog
import Compression


public class ProcessHelpers {
    // MARK: Supported scripting interpreters
    static let supportedInterpreters: Set<String> = [
        "bash",
        "osascript",
        "ruby",
        "perl",
        "python",
        "node",
        "bun",
        "swift"
    ]
    
    /// Is `executableName` a supported scripting interpreter: one of ``supportedInterpreters``, alone or followed by a
    /// version (`python3`, `python3.12`, `ruby3.3`)? Names that only start with one (`bundle`, `bunzip2`,
    /// `swift-frontend`) aren't.
    ///
    /// - Parameter executableName: The executable's file name.
    /// - Returns: Whether to look for the script among the exec's arguments.
    static func isScriptingInterpreter(_ executableName: String) -> Bool {
        supportedInterpreters.contains { interpreter in
            guard executableName.hasPrefix(interpreter) else { return false }
            return executableName.dropFirst(interpreter.count).allSatisfy { $0.isNumber || $0 == "." }
        }
    }
    
    
    // MARK: - Parsing the arguments of exec events
    static func parseExecArgs(execEvent: inout es_event_exec_t) -> [String] {
        var args: [String] = []
        for i in 0 ..< Int(es_exec_arg_count(&execEvent)) {
            args.append(es_exec_arg(&execEvent, UInt32(i)).string ?? "")
        }
        return args
    }
    
    static func parseScriptFromArgs(args: [String], workingDirectory: String) -> String? {
        guard args.count > 1 else { return nil }
        
        for arg in args.dropFirst() {
            guard !arg.hasPrefix("-") else { continue }
            let pathToCheck: String
            if arg.hasPrefix("/") {
                pathToCheck = arg
            } else {
                pathToCheck = (workingDirectory as NSString).appendingPathComponent(arg)
            }
            
            if fileIsNonBinary(at: pathToCheck) {
                return pathToCheck
            }
        }
        
        return nil
    }
    
    // MARK: - Parsing the evnvironment variables of exec events
    public static func parseExecEnvVars(event: inout es_event_exec_t) -> String {
        let numberOfVars: Int = Int(es_exec_env_count(&event))
        var envVars: [String] = []
        
        for index in 0..<numberOfVars {
            let envVarVar: String = es_exec_env(&event, UInt32(index)).string ?? ""
            envVars.append(envVarVar)
        }
        return envVars.joined(separator: "[::]")
    }
    
    public static func parseExecEnv(event: inout es_event_exec_t) -> [String] {
        let count: Int = Int(es_exec_env_count(&event))
        var env: [String] = []
        
        for index in 0..<count {
            let envVarVar: String = es_exec_env(&event, UInt32(index)).string ?? ""
            env.append(envVarVar)
        }
        return env
    }
    
    // MARK: - Parsing the open file descriptors of exec events
    public static func getFds(event: inout es_event_exec_t) -> [FileDescriptor] {
        let count = Int(es_exec_fd_count(&event))
        var fds: [FileDescriptor] = []
        
        for index in 0..<count {
            let fd: es_fd_t = es_exec_fd(&event, UInt32(index)).pointee
            fds.append(FileDescriptor(from: fd))
        }
        
        return fds
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
    public static func eventToJSON(value: Encodable) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        
        do {
            let encodedData = try encoder.encode(value)
            return String(data: encodedData, encoding: .utf8) ?? ""
        } catch {
            return "{}"
        }
    }
    
    public static func eventToPrettyJSON(value: Encodable) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        
        do {
            let encodedData = try encoder.encode(value)
            return String(data: encodedData, encoding: .utf8) ?? ""
        } catch {
            return "{}"
        }
    }
    
    // MARK: - Add to when supporting new ES events (if it has a process struct)
    public static func getTargetProcessName(message: ESMessage) -> String {
        let event = message.event
        if let exec = event.exec,
           let exe = exec.target.executable {
            return exe.name
        } else if let fork = event.fork {
            return fork.child.executable?.name ?? ""
        } else if let _ = event.exit,
                  let exe = message.process.executable {
            return exe.name
        }
        
        if let exe = message.process.executable {
            return exe.name
        }
        
        return "EVENTS_CLEARED"
    }
    
    // Compress JSON representation with the Apple recommended compression algo LZFSE
    // https://developer.apple.com/documentation/compression/algorithm/lzfse
    public static func getCompressedJSON(from rcEvent: Message) -> Data {
        let json_representation: String = ProcessHelpers.eventToJSON(value: rcEvent)
        var sourceBuffer = Array(json_representation.utf8)
        let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: json_representation.count)
        let algorithm = COMPRESSION_LZFSE
        let compressedSize = compression_encode_buffer(destinationBuffer, json_representation.count,
                                                       &sourceBuffer, json_representation.count,
                                                       nil,
                                                       algorithm)
        if compressedSize == 0 {
            os_log("Encoding failed.")
        }
        
        return NSData(bytesNoCopy: destinationBuffer, length: compressedSize) as Data
    }
    
    //    public static func decompressJSON(from rcEvent: RCEvent) -> String {
    //        let json_representation: String = RCProcessHelpers.eventToJSON(value: rcEvent)
    //        var sourceBuffer = Array(json_representation.utf8)
    //        let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: json_representation.count)
    //        let algorithm = COMPRESSION_LZFSE
    //        let decodedSize = compression_decode_buffer(destinationBuffer,
    //                                                    inputDataSize,
    //                                                    &sourceBuffer,
    //                                                    compressedSize,
    //                                                    nil,
    //                                                    algorithm)
    //        if compressedSize == 0 {
    //            os_log("Encoding failed.")
    //        }
    //    }
    
    // MARK: - Process event helper functions
    public static func timespecToTimestamp(timespec: timespec) -> Date {
        let unixTimestamp = Double(timespec.tv_sec) + (Double(timespec.tv_nsec) / 1e9)
        let date = Date(timeIntervalSince1970: unixTimestamp)
        
        return date
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
    
    public static func timevalToTimestamp(timeval: timeval) -> String {
        let unixTimestamp = Double(timeval.tv_sec) + (Double(timeval.tv_usec) / 1000000)
        let date = Date(timeIntervalSince1970: unixTimestamp)
        return timestampFormatter.string(from: date)
    }
    
    public static func procInfoToString(procInfo: proc_uniqidentifierinfo) -> String {
        // @discussion: Matching Jamf Protect: We're only using UUID from `PROC_PIDUNIQIDENTIFIERINFO`
        // @note old string: `%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x-%llu-%llu-%d`
        // This is not the same UUID as the one pulled from `PROC_PIDUNIQIDENTIFIERINFO`
        return String(format: "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      procInfo.p_uuid.0, procInfo.p_uuid.1, procInfo.p_uuid.2, procInfo.p_uuid.3,
                      procInfo.p_uuid.4, procInfo.p_uuid.5, procInfo.p_uuid.6, procInfo.p_uuid.7,
                      procInfo.p_uuid.8, procInfo.p_uuid.9, procInfo.p_uuid.10, procInfo.p_uuid.11,
                      procInfo.p_uuid.12, procInfo.p_uuid.13, procInfo.p_uuid.14, procInfo.p_uuid.15)
    }
    
    // MARK: - Reading scripts and plists
    /// The most bytes ``getFileContents(at:)`` reads: a longer script or plist is cut there.
    static let fileContentsLimit = 1 << 20
    
    /// Does a path name a regular file whose first 512 bytes are UTF-8 text, such as a script?
    ///
    /// - Parameter path: The file's path, or a `file://` URL's.
    /// - Returns: `false` for a binary, or anything that isn't a regular file (``openRegularFile(at:)``).
    static func fileIsNonBinary(at path: String) -> Bool {
        guard let file = openRegularFile(at: path), let data = try? file.read(upToCount: 512) else {
            return false
        }
        return String(data: data, encoding: .utf8) != nil
    }
    
    /// The UTF-8 text of a regular file, such as a script or a launch item's plist, up to ``fileContentsLimit``.
    ///
    /// - Parameter path: The file's path, or a `file://` URL's.
    /// - Returns: The text, cut at the limit back to the end of a whole character, or `nil` if the file isn't UTF-8
    ///   text or isn't a regular file (``openRegularFile(at:)``).
    public static func getFileContents(at path: String) -> String? {
        guard let file = openRegularFile(at: path) else { return nil }
        let data: Data
        do {
            data = try file.read(upToCount: fileContentsLimit + 1) ?? Data()
        } catch {
            return nil
        }
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
    /// writing, and the capture lane building the event waited with it; opening a device can have side effects. So the
    /// path is `stat`ed first, opened with `O_NONBLOCK`, and checked again with `fstat` in case it was replaced in
    /// between.
    ///
    /// - Parameter path: The file's path, or a `file://` URL's. A symbolic link is followed.
    /// - Returns: The open file, closed when it's released, or `nil` if the path doesn't name a regular file or it
    ///   can't be opened.
    static func openRegularFile(at path: String) -> FileHandle? {
        let path = URL(fileURLWithPath: String(path.trimmingPrefix("file://"))).path
        var info = stat()
        guard stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        return file
    }
}
