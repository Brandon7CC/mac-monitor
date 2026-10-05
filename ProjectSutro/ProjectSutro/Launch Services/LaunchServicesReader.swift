//
//  LaunchServicesReader.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


// MARK: - LaunchServices reader
/// Reads LaunchServices' records of the apps it launched, so Mac Monitor can name who asked for each launch
/// (``LaunchedByParentUpgrader``).
///
/// LaunchServices has no public call for that. This uses the private calls `lsappinfo(1)` is built on, looked up at
/// run time, so a macOS without them reads nothing and its apps' launched-by parents stay launchd jobs:
/// ```c
/// LSASNRef        _LSASNCreateWithPid(CFAllocatorRef, pid_t);                              // no IPC
/// CFDictionaryRef _LSCopyApplicationInformation(LSSessionID, LSASNRef, CFArrayRef keys);  // -2: caller's session
/// ```
/// A read asks for the app's record with only the three keys it needs, then for the launcher's `LSAuditToken` and
/// executable path: LaunchServices keeps the launcher's record a while after it quits, when its pid no longer names
/// it. The calls are exported in the macOS 26.5 and 27 SDKs and were read on macOS 27; macOS 13 to 15 aren't checked
/// yet.
///
/// About 0.03-0.3 ms a read (about 1 ms for the first): never on the main queue. In the app only: the Security
/// Extension never contains these calls.
final class LaunchServicesReader: LaunchServicesReading {
    /// The reader Mac Monitor gives its upgrader.
    static let shared = LaunchServicesReader()
    
    /// LaunchServices' record of a process in Mac Monitor's audit session.
    ///
    /// - Parameter pid: The process's pid.
    /// - Returns: The record, or `nil` when there's none (yet, or any more), it has no `LSAuditToken`, or the calls
    ///   are missing.
    func record(forPID pid: pid_t) -> LaunchServicesRecord? {
        guard let record = Self.information(SPI.asn(pid), keys: [Key.auditToken, Key.launched, Key.parentASN]),
              let token = Self.token(record[Key.auditToken]) else { return nil }
        let parentASN = record[Key.parentASN]
        let parent = parentASN.flatMap { Self.information($0 as AnyObject, keys: [Key.auditToken, Key.executable]) }
        return LaunchServicesRecord(token: token, launchedByLaunchServices: record[Key.launched] as? Bool ?? false,
                                    hasParentASN: parentASN != nil, parentToken: Self.token(parent?[Key.auditToken]),
                                    parentPath: parent?[Key.executable] as? String)
    }
    
    /// Some of a record, in the caller's audit session.
    ///
    /// - Parameters:
    ///   - asn: The app's `LSASNRef`.
    ///   - keys: The keys to read.
    /// - Returns: The record's values for those keys, or `nil` without a record or the calls.
    private static func information(_ asn: AnyObject?, keys: [String]) -> [String: Any]? {
        guard let asn, let copyInformation = SPI.copyInformation else { return nil }
        return copyInformation(SPI.callerSession, asn, keys as CFArray)?.takeRetainedValue() as? [String: Any]
    }
    
    /// An `LSAuditToken` value.
    ///
    /// - Parameter value: The record's value: `audit_token_t`'s 32 bytes.
    /// - Returns: The token, or `nil` when the value isn't one.
    private static func token(_ value: Any?) -> AuditToken? {
        (value as? Data).flatMap(AuditToken.init(auditTokenData:))
    }
    
    /// The record's keys: LaunchServices' exported constants, or the values they have on macOS 27.
    private enum Key {
        /// The process that checked in.
        static let auditToken = SPI.string("_kLSAuditTokenKey") ?? "LSAuditToken"
        /// Did LaunchServices launch it?
        static let launched = SPI.string("_kLSLaunchedByLaunchServicesKey") ?? "LSLaunchedByLaunchServices"
        /// The launcher's `LSASNRef`.
        static let parentASN = SPI.string("_kLSParentASNKey") ?? "LSParentASN"
        /// An app's executable.
        static let executable = SPI.string("_kLSExecutablePathKey") ?? "CFBundleExecutablePath"
    }
    
    /// LaunchServices' private calls and constants, each looked up once.
    private enum SPI {
        /// `_LSASNCreateWithPid`.
        typealias ASNWithPID = @convention(c) (CFAllocator?, pid_t) -> Unmanaged<AnyObject>?
        /// `_LSCopyApplicationInformation`.
        typealias CopyInformation = @convention(c) (Int32, AnyObject?, CFArray?) -> Unmanaged<CFDictionary>?
        
        /// `kLSDefaultSessionID`: the caller's audit session.
        static let callerSession: Int32 = -2
        /// CoreServices, which every app has loaded already.
        static let handle = dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY)
        /// `_LSASNCreateWithPid`, or `nil` when it isn't exported.
        static let asnWithPID = handle.flatMap { dlsym($0, "_LSASNCreateWithPid") }
            .map { unsafeBitCast($0, to: ASNWithPID.self) }
        /// `_LSCopyApplicationInformation`, or `nil` when it isn't exported.
        static let copyInformation = handle.flatMap { dlsym($0, "_LSCopyApplicationInformation") }
            .map { unsafeBitCast($0, to: CopyInformation.self) }
        
        /// An app's `LSASNRef`, made from its pid without asking LaunchServices.
        ///
        /// - Parameter pid: The app's pid.
        /// - Returns: The reference, or `nil` without the call.
        static func asn(_ pid: pid_t) -> AnyObject? {
            asnWithPID?(kCFAllocatorDefault, pid)?.takeRetainedValue()
        }
        
        /// One of LaunchServices' exported string constants.
        ///
        /// - Parameter name: Its symbol.
        /// - Returns: Its value, or `nil` when it isn't exported.
        static func string(_ name: String) -> String? {
            guard let symbol = handle.flatMap({ dlsym($0, name) }) else { return nil }
            return symbol.load(as: Unmanaged<CFString>?.self)?.takeUnretainedValue() as String?
        }
    }
}
