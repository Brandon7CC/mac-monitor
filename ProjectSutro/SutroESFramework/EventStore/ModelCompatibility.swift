//
//  ModelCompatibility.swift
//  SutroESFramework
//
//  Compatibility layer bridging the old Core Data model names (ESMessage, ESProcess, etc.)
//  to the shared Codable models (Message, Process, etc.).
//
//  This allows all existing SwiftUI views to compile with zero changes while
//  the entire Core Data layer is removed. The ES* typealiases will be removed
//  incrementally as views are updated to use the canonical names.
//

import Foundation

// MARK: - Type Aliases
// Maps old Core Data class names → shared Codable struct names.
// These should be removed over time as views adopt the canonical names.

public typealias ESMessage = Message
public typealias ESProcess = Process
public typealias ESEventType = EventType
public typealias ESFile = File
public typealias ESAuditToken = AuditToken
public typealias ESThread = Thread

// Event type aliases
public typealias ESProcessExecEvent = ProcessExecEvent
public typealias ESProcessForkEvent = ProcessForkEvent
public typealias ESProcessExitEvent = ProcessExitEvent
public typealias ESProcessSignalEvent = ProcessSignalEvent
public typealias ESProcessSocketEvent = ProcessSocketEvent
public typealias ESProcessCheckEvent = ProcessCheckEvent
public typealias ESProcessTraceEvent = ProcessTraceEvent
public typealias ESRemoteThreadCreateEvent = RemoteThreadCreateEvent
public typealias ESCodeSignatureInvalidatedEvent = CodeSignatureInvalidatedEvent
public typealias ESMMapEvent = MMapEvent
public typealias ESMProtectEvent = MProtectEvent
public typealias ESFileCreateEvent = FileCreateEvent
public typealias ESFileRenameEvent = FileRenameEvent
public typealias ESFileOpenEvent = FileOpenEvent
public typealias ESFileWriteEvent = FileWriteEvent
public typealias ESFileCloseEvent = FileCloseEvent
public typealias ESFileDeleteEvent = FileDeleteEvent
public typealias ESFDDuplicateEvent = FDDuplicateEvent
public typealias ESLinkEvent = LinkEvent
public typealias ESXattrSetEvent = XattrSetEvent
public typealias ESXattrGetEvent = XattrGetEvent
public typealias ESXattrListEvent = XattrListEvent
public typealias ESXattrDeleteEvent = XattrDeleteEvent
public typealias ESSetModeEvent = SetModeEvent
public typealias ESPTYGrantEvent = PTYGrantEvent
public typealias ESMountEvent = MountEvent
public typealias ESLoginLoginEvent = LoginLoginEvent
public typealias ESLWLoginEvent = LWLoginEvent
public typealias ESLWUnlockEvent = LWUnlockEvent
public typealias ESOpenSSHLoginEvent = SSHLoginEvent
public typealias ESOpenSSHLogoutEvent = SSHLogoutEvent
public typealias ESIOKitOpenEvent = IOKitOpenEvent
public typealias ESAuthorizationPetitionEvent = AuthorizationPetitionEvent
public typealias ESAuthorizationJudgementEvent = AuthorizationJudgementEvent
public typealias ESGetTaskEvent = GetTaskEvent
public typealias ESProfileAddEvent = ProfileAddEvent
public typealias ESLaunchItemAddEvent = LaunchItemAddEvent
public typealias ESLaunchItemRemoveEvent = LaunchItemRemoveEvent
public typealias ESXProtectDetect = XProtectDetectEvent
public typealias ESXProtectRemediate = XProtecRemediateEvent
public typealias ESODCreateUserEvent = OpenDirectoryCreateUserEvent
public typealias ESODModifyPasswordEvent = OpenDirectoryModifyPasswordEvent
public typealias ESODGroupAddEvent = OpenDirectoryGroupAddEvent
public typealias ESODGroupRemoveEvent = OpenDirectoryGroupRemoveEvent
public typealias ESODCreateGroupEvent = OpenDirectoryCreateGroupEvent
public typealias ESODAttributeValueAddEvent = OpenDirectoryAttributeValueAddEvent
public typealias ESXPCConnectEvent = XPCConnectEvent
public typealias ESUIPCConnectEvent = UIPCConnectEvent
public typealias ESUIPCBindEvent = UIPCBindEvent
public typealias ESTCCModifyEvent = TCCModifyEvent
public typealias ESGatekeeperUserOverrideEvent = GatekeeperUserOverrideEvent

// Artifact aliases
public typealias ESLaunchItem = LaunchItem
public typealias ESProfile = Profile


// MARK: - Message compatibility extensions

extension Message {
    /// Compatibility: Core Data stored version as Int32
    public var es_event_type_compat: String? { es_event_type }

    /// Compatibility: Sortable proxies (previously defined as ESMessage extensions)
    public var sortableTimestamp: TimeInterval { message_darwin_time.timeIntervalSince1970 }
    public var sortEffectiveUser: String       { process.euid_human       ?? "" }
    public var sortSourceProcess: String       { process.executable?.name ?? "" }
    public var sortSourceSigningID: String     { process.signing_id       ?? "" }
    public var sortSourceProcessPath: String   { process.executable?.path ?? "" }
    public var sortEventType: String           { es_event_type }
    public var sortContext: String             { context ?? "" }
}


// MARK: - Process compatibility extensions

extension Process {
    /// Compatibility: Core Data `ESProcess` stored `euid` as `Int64`.
    /// The `Process` struct stores it as `Int?`.
    public var euid_int64: Int64 { Int64(euid ?? 0) }
    public var ruid_int64: Int64 { Int64(ruid ?? 0) }

    /// Compatibility: `file_quarantine_type` was stored as a raw value `String` in Core Data.
    public var file_quarantine_type_string: String { file_quarantine_type.rawValue }
    /// Compatibility: `codesigning_type` was stored as a raw value `String` in Core Data.
    public var codesigning_type_string: String { codesigning_type.rawValue }
}


// MARK: - AuditToken compatibility

extension AuditToken {
    /// Compatibility: `ESAuditToken` had a `toString()` method.
    public func toString() -> String {
        "pid:\(pid), euid:\(euid), ruid:\(ruid), rgid:\(rgid), egid:\(egid), asid:\(asid), auid:\(auid), pidversion:\(pidversion)"
    }
}
