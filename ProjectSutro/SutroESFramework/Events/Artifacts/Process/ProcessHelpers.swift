//
//  RCProcessHelpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//

import Foundation
import OSLog
import Compression
import CryptoKit
//import SwiftCSBlobs


public class ProcessHelpers {
    // MARK: - Parsing the command line of exec events
    static func parseCommandLine(execEvent: inout es_event_exec_t) -> String {
        var command_line_builder: String = ""
        for i in 0 ..< Int(es_exec_arg_count(&execEvent)) {
            command_line_builder = "\(command_line_builder) \(String(cString: es_exec_arg(&execEvent, UInt32(i)).data))"
        }
        return command_line_builder.trimmingCharacters(in: .whitespaces)
    }
    
    static func parseExecArgs(execEvent: inout es_event_exec_t) -> [String] {
        var args: [String] = []
        for i in 0 ..< Int(es_exec_arg_count(&execEvent)) {
            let arg: String = String(cString: es_exec_arg(&execEvent, UInt32(i)).data).trimmingCharacters(
                in: .whitespaces
            )
            args.append(arg)
        }
        return args
    }
    
    // MARK: - Parsing the evnvironment variables of exec events
    public static func parseExecEnvVars(event: inout es_event_exec_t) -> String {
        let numberOfVars: Int = Int(es_exec_env_count(&event))
        var envVars: [String] = []
        
        for index in 0..<numberOfVars {
            let envVarVar: String = String(cString: es_exec_env(&event, UInt32(index)).data)
            envVars.append(envVarVar)
        }
        return envVars.joined(separator: "[::]")
    }
    
    public static func parseExecEnv(event: inout es_event_exec_t) -> [String] {
        let count: Int = Int(es_exec_env_count(&event))
        var env: [String] = []
        
        for index in 0..<count {
            let envVarVar: String = String(cString: es_exec_env(&event, UInt32(index)).data)
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
    
    public static func timevalToTimestamp(timeval: timeval) -> String {
        let unixTimestamp = Double(timeval.tv_sec) + (Double(timeval.tv_usec) / 1000000)
        let date = Date(timeIntervalSince1970: unixTimestamp)
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return dateFormatter.string(from: date)
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
    
    
    public static func getCodeSigningCerts(forBinaryAt path: String) -> [X509Cert] {
        var staticCode: SecStaticCode?
        guard let url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path as CFString, .cfurlposixPathStyle, false) else {
            return []
        }
        
        let createFlags: SecCSFlags = []
        var status = SecStaticCodeCreateWithPath(url, createFlags, &staticCode)
        
        guard status == errSecSuccess, let staticCode = staticCode else {
            return []
        }
        
        var dict: CFDictionary?
        let infoFlags: SecCSFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        status = SecCodeCopySigningInformation(staticCode, infoFlags, &dict)
        guard status == errSecSuccess, let infoDict = dict as? [String: Any] else {
            return []
        }
        
        let certificateChainKey = kSecCodeInfoCertificates as String
        guard let certificateChain = infoDict[certificateChainKey] as? [SecCertificate] else {
            return []
        }
                
        var chain: [X509Cert] = []
        for (index, certificate) in certificateChain.enumerated() {
            if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
                let certificateData = SecCertificateCopyData(certificate) as Data
                let thumbprint: String = Insecure.SHA1.hash(data: certificateData).map { String(format: "%02hhx", $0) }.joined()
                chain.append(X509Cert(summary: summary, thumbprint: thumbprint))
            }
        }
        
        return chain
    }
    
    // TODO: Comment / clenaup and add support for Apple binary property lists
    public static func getFileContents(at path: String) -> String? {
        let modPath = String(path.trimmingPrefix("file://"))
        let fileURL = URL(fileURLWithPath: modPath)
        
        // Check if the file exists
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            // Return nil if the file does not exist
            return nil
        }
        
        // Read the contents of the file
        do {
            let fileContents = try String(contentsOf: fileURL)
            return fileContents
        } catch {
            // Handle error
            return nil
        }
    }
    
    /// Returns 1 if the file is quarantined, 0 if not, and 2 if the file is not found
    public static func isFileQuarantined(filePath: String) -> Int {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: filePath) {
            return getxattr(filePath, "com.apple.quarantine", nil, 0, 0, 0) > 0 ? 1 : 0
        } else {
            return 2
        }
    }
    
    
    public static func newIsFileQuarantined(filePath: String) -> Bool {
        let url = URL(fileURLWithPath: filePath)
        let resourceValues = try? url.resourceValues(forKeys:[.quarantinePropertiesKey])
        let quarantineProperties = resourceValues?.quarantineProperties
        return quarantineProperties != nil
    }
    
    // MARK: - Code Signing Type
    public static func codeSigningType(for process: es_process_t) -> CodeSigningType {
        // Helper function to determine type from certificates
        func certType(forPath path: String) -> CodeSigningType? {
            let certificates = ProcessHelpers.getCodeSigningCerts(forBinaryAt: path)
            
            for cert in certificates {
                let summary = cert.summary
                if summary.hasPrefix("Apple Mac OS") {
                    return .appStore
                } else if summary.hasPrefix("Developer ID Application") {
                    return .developerId
                }
            }
            return nil
        }
        
        // Platform binary
        if process.is_platform_binary {
            return .platform
        }
        
        // Adhoc binary
        if (Int(process.codesigning_flags) & Int(CS_ADHOC)) == Int(CS_ADHOC) {
            return .adhoc
        }
        
        // Is validly signed
        let csValid = (Int32(process.codesigning_flags) & CS_VALID) == CS_VALID
        if csValid && process.executable.pointee.path.length > 0 {
            let executablePath = String(
                cString: process.executable.pointee.path.data
            )
            
            // Check the codesinging certificates
            if let type = certType(forPath: executablePath) {
                return type
            }
            
            return .unknown
        }
        
        // Not validly signed
        return .unsigned
    }
    
    
    // MARK: - LSFileQuarantineEnabled check
    
    /// Which bundle identifiers are forced into File Quarantine?
    ///
    /// Bundle identifiers forced into File Quarantine by Apple are located in a property list file by the name of `Exceptions.plist`.
    /// We read from that property list and pull out all identiifers with a `LSFileQuarantineEnabled` key value set to `true`.
    ///
    public static let forcedQuarantineSigningIDs: [String] = {
        var signingIDs: [String] = []
        let filePath = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/Exceptions.plist"

        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = plist as? [String: Any],
              let entries = dict["Additions"] as? [String: Any] else {
            return signingIDs
        }

        for (key, value) in entries {
            if let data = value as? [String: Any], data["LSFileQuarantineEnabled"] != nil {
                signingIDs.append(key)
            }
        }

        return signingIDs
    }()
    
    /// The cache we use for paths we've already checked
    private static let quarantineCheckCache: NSCache<NSString, NSNumber> = {
        let cache = NSCache<NSString, NSNumber>()
        cache.countLimit = 1000
        return cache
    }()
    
    /// Given the path to an executable on-disk return if it's "File Quarantine-aware".
    ///
    /// This method checks if an executable application has the `LSFileQuarantineEnabled` key
    /// set to `true` in its Info.plist file. Applications with this flag enabled respect in file quarantine.
    ///
    /// - Parameter path: The file path to the executable to check
    /// - Returns: `true` if the executable has quarantine enabled, `false` otherwise
    ///
    /// The method uses an internal cache to avoid repeated disk access and plist parsing
    /// for paths that have already been checked. The cache has a limit of 1000 entries.
    public static func isQuarantineEnabled(forExecutableAt path: String, signingId: String?) -> FileQuarantineType {
        /// We're only going to check for File Quarantine with app bundles.
        if !path.contains(".app") {
            return .disabled
        }
        
        /// First, check if Apple has forced the executable into being File Quarantine-aware
        if let signingId = signingId,
           forcedQuarantineSigningIDs.contains(signingId) {
            return .forced
        }
        
        /// Second, check if the path is in the cache
        let nsPath = path as NSString
        if let cached = quarantineCheckCache.object(forKey: nsPath) {
            return cached.boolValue ? .optIn : .disabled
        }
        
        let components = URL(fileURLWithPath: path).pathComponents
        guard let contentsIndex = components.firstIndex(of: "Contents") else {
            quarantineCheckCache.setObject(NSNumber(value: false), forKey: nsPath)
            return .disabled
        }
        
        /// Third, check if `LSFileQuarantineEnabled` is in the plist
        let plistPath = NSString.path(withComponents: Array(components.prefix(through: contentsIndex)) + ["Info.plist"])
        guard FileManager.default.fileExists(atPath: plistPath),
              let dict = NSDictionary(contentsOfFile: plistPath),
              let quarantineEnabled = dict["LSFileQuarantineEnabled"] as? Bool else {
            quarantineCheckCache.setObject(NSNumber(value: false), forKey: nsPath)
            return .disabled
        }
        
        // Cache the result we found in the plist
        quarantineCheckCache.setObject(NSNumber(value: quarantineEnabled), forKey: nsPath)
        return quarantineEnabled ? .optIn : .disabled
    }
}
