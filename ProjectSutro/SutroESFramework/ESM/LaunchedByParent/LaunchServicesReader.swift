//
//  LaunchServicesReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launch Services reader
/// Reads Launch Services' records of the apps it launched, so the Security Extension can name who asked for each
/// launch (``LaunchedByParentUpgrader``).
///
/// There's no public API for this. We use the private calls `lsappinfo(1)` is built on and look them up at run time.
/// On a macOS without them we read nothing, and apps keep their launchd job as the launched-by parent.
/// ```c
/// LSASNRef        _LSASNCreateWithPid(CFAllocatorRef, pid_t);                              // no IPC
/// CFDictionaryRef _LSCopyApplicationInformation(LSSessionID, LSASNRef, CFArrayRef keys);  // -2: default session
/// ```
/// Each read asks for the three keys we need from the app's record. Then it reads the launcher's `LSAuditToken` and
/// executable path from the launcher's own record. Launch Services keeps that record for a while after the launcher
/// quits, so we can still name it after its pid is gone.
///
/// Session `-2` isn't limited to the caller's login session. On macOS 27, running as root from an SSH session, it
/// returned the console user's apps. Passing their audit session ID returned nothing. That's why the Security
/// Extension can read these records even though it runs outside any login session.
///
/// The calls are exported in the macOS 26.5 and 27 SDKs and we've tested them on macOS 27. macOS 13 to 15 haven't been
/// checked yet. A read takes about 0.03-0.3 ms (about 1 ms the first time), so never call it on a handler queue.
final class LaunchServicesReader: LaunchServicesReading {
    /// The reader every live capture session uses
    static let shared = LaunchServicesReader()
    
    /// LaunchServices' record of a process.
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
    
    /// Read some keys of a record from Launch Services' default session.
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
        
        /// `kLSDefaultSessionID`, Launch Services' default session
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
