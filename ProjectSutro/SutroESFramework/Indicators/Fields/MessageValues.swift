//
//  MessageValues.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Message values
/// An event's values for the fields the Security Extension evaluates indicators on (``IndicatorField``), read from
/// the `Message` a capture lane builds, before it's encoded or stored. Each is the value a predicate on the event's
/// record compares there (`ESMessage(from:)` encoded, read as ``PredicateRecord`` reads it), which
/// `MessageValuesParityTests` checks for every field on every event of the synthetic corpus, the fixtures, the lineage
/// trace and the macath recordings:
///
/// - `context` and `target_path` are "Not supported" where the event has none, as the store writes them.
/// - An exec's `command_line` is "" where it has none.
/// - A process's `codesigning_type` and `file_quarantine_type` are "" when it has no executable: the store keeps
///   them only beside one.
/// - An executable's `name` is its path's last component, as `File/name` is.
/// - `iokit_open.driver_bundle_id` is `nil` before message version 10, which the store doesn't keep it for.
/// - A field of another event type than the event's is `nil`, as the record has no such object.
///
/// The message is borrowed: each read goes through one `switch` on the event to the one leaf it needs, and copies
/// none of the message, its event's payload or a process's executable on the way (an optimized build's disassembly
/// shows none of them copied). A string comes back as a slice of the event's own, which only retains its storage.
public enum MessageValues {
    /// What the store writes for an event's `context` or `target_path` when it has none.
    static let notSupported = "Not supported"

    /// One field's value on an event. A record field is read from the event's encoding alone, which a lane does
    /// once for all of its set's (``MessageValueCache``).
    ///
    /// - Parameters:
    ///   - field: The field.
    ///   - message: The event.
    /// - Returns: The value its record has there.
    public static func value(of field: IndicatorField, in message: borrowing Message) -> IndicatorValue {
        /// An ancestor's field isn't the event's: only a lane's cache, which has the lineage table, reads one.
        if field.lineageOffset != nil { return .null }
        guard field.isDirect else {
            var value = IndicatorValue.null
            RecordPathTrie([field]).read(message) { _, found in value = found }
            return value
        }
        if message.event.isNetworkFlow, let value = flowValue(of: field, in: message.process) { return value }
        return switch field {
        case .esEventType: IndicatorValue(message.es_event_type)
        case .context: IndicatorValue(message.context ?? notSupported)
        case .targetPath: IndicatorValue(message.target_path ?? notSupported)
        case .processExecutablePath: process(.executablePath, of: message.process)
        case .processExecutableName: process(.executableName, of: message.process)
        case .processSigningID: process(.signingID, of: message.process)
        case .processTeamID: process(.teamID, of: message.process)
        case .processIsPlatformBinary: process(.isPlatformBinary, of: message.process)
        case .processCodesigningType: process(.codesigningType, of: message.process)
        case .processIsAdhocSigned: process(.isAdhocSigned, of: message.process)
        case .processFileQuarantineType: process(.fileQuarantineType, of: message.process)
        default: event(field, of: message.event, version: message.version)
        }
    }

    /// A direct field a network flow's record has otherwise than an Endpoint Security event's: no `es_event_type`,
    /// and its process as `flow_process` (``FlowProcessRecord``), which has no platform binary, adhoc or quarantine
    /// flag, and a code signing type only beside an executable and when it's known.
    ///
    /// - Parameters:
    ///   - field: A direct field.
    ///   - process: The flow's process.
    /// - Returns: The value, or `nil` for a field read as any event's.
    private static func flowValue(of field: IndicatorField, in process: borrowing Process) -> IndicatorValue? {
        switch field {
        case .esEventType, .processIsPlatformBinary, .processIsAdhocSigned, .processFileQuarantineType:
            return .null
        case .processCodesigningType:
            guard case .some = process.executable, process.codesigning_type != .unknown else { return .null }
            return IndicatorValue(process.codesigning_type.rawValue)
        default:
            return nil
        }
    }

    /// A field of the event's own object, under `event`.
    ///
    /// - Parameters:
    ///   - field: A field under `event`.
    ///   - event: The event.
    ///   - version: The message's version.
    /// - Returns: The value, or ``IndicatorValue/null`` when the event is of another type.
    private static func event(_ field: IndicatorField, of event: EventType, version: Int) -> IndicatorValue {
        switch event {
        case .exec(let exec): Self.exec(field, of: exec)
        case .close(let close) where field == .closeModified: IndicatorValue(close.modified)
        case .close(let close) where field == .closeFileType: IndicatorValue(close.file_type)
        case .close(let close) where field == .closeMachOType: IndicatorValue(close.mach_o_type)
        case .close(let close) where field == .closeTargetName: name(ofPath: close.target.path)
        case .create(let create) where field == .createIsQuarantined: IndicatorValue(Int(create.is_quarantined))
        case .deleteextattr(let xattr) where field == .deleteextattrExtattr: IndicatorValue(xattr.extattr)
        case .iokit_open(let open) where field == .iokitOpenDriverBundleID && version >= 10:
            IndicatorValue(open.driver_bundle_id)
        case .iokit_open(let open) where field == .iokitOpenUserClientClass: IndicatorValue(open.user_client_class)
        case .uipc_connect(let connect) where field == .uipcConnectFileStatUID:
            IndicatorValue(Int(connect.file.stat.st_uid))
        case .xpc_connect(let connect) where field == .xpcConnectServiceName: IndicatorValue(connect.service_name)
        case .xpc_connect(let connect) where field == .xpcConnectServiceDomainTypeString:
            IndicatorValue(connect.service_domain_type_string)
        default: .null
        }
    }

    /// A field under `event.exec`.
    ///
    /// - Parameters:
    ///   - field: A field.
    ///   - exec: The exec.
    /// - Returns: The value, or ``IndicatorValue/null`` for a field that isn't under `event.exec`.
    private static func exec(_ field: IndicatorField, of exec: borrowing ProcessExecEvent) -> IndicatorValue {
        switch field {
        case .execCommandLine: IndicatorValue(exec.command_line ?? "")
        case .execEnv: .strings(exec.env)
        case .execArgsCount: IndicatorValue(exec.args.count)
        case .execEnvCount: IndicatorValue(exec.env.count)
        case .execScriptContent: IndicatorValue(exec.script_content)
        case .execExecutableAge: IndicatorValue(exec.executable_age_ms)
        case .execTargetSigningID: process(.signingID, of: exec.target)
        case .execTargetTeamID: process(.teamID, of: exec.target)
        case .execTargetIsPlatformBinary: process(.isPlatformBinary, of: exec.target)
        case .execTargetIsAdhocSigned: process(.isAdhocSigned, of: exec.target)
        case .execTargetCodesigningType: process(.codesigningType, of: exec.target)
        case .execTargetExecutablePath: process(.executablePath, of: exec.target)
        case .execTargetExecutableName: process(.executableName, of: exec.target)
        case .execTargetEUID: IndicatorValue(exec.target.euid)
        case .execTargetRUID: IndicatorValue(exec.target.ruid)
        default: .null
        }
    }

    /// A process's value that a field reads: the initiating process's, or an exec target's.
    private enum ProcessLeaf {
        case signingID, teamID, isPlatformBinary, isAdhocSigned, codesigningType, executablePath, executableName
        case fileQuarantineType
    }

    /// One of a process's values.
    ///
    /// - Parameters:
    ///   - leaf: The value.
    ///   - process: The process.
    /// - Returns: The value its record has.
    private static func process(_ leaf: ProcessLeaf, of process: borrowing Process) -> IndicatorValue {
        switch leaf {
        case .signingID: IndicatorValue(process.signing_id)
        case .teamID: IndicatorValue(process.team_id)
        case .isPlatformBinary: IndicatorValue(process.is_platform_binary)
        case .isAdhocSigned: IndicatorValue(process.is_adhoc_signed)
        case .codesigningType: besideExecutable(process.codesigning_type.rawValue, of: process)
        case .executablePath: IndicatorValue(process.executable?.path)
        case .executableName: name(ofPath: process.executable?.path)
        case .fileQuarantineType: besideExecutable(process.file_quarantine_type.rawValue, of: process)
        }
    }

    /// A process's `codesigning_type` or `file_quarantine_type`, which the store keeps only beside an executable: ""
    /// without one.
    ///
    /// The executable is tested with a pattern, not `== nil`, which would compare a copy of it by `File`'s `==`.
    ///
    /// - Parameters:
    ///   - type: The type's raw value.
    ///   - process: The process.
    /// - Returns: The raw value, or "" without an executable.
    private static func besideExecutable(_ type: String, of process: borrowing Process) -> IndicatorValue {
        if case .none = process.executable { return IndicatorValue("") }
        return IndicatorValue(type)
    }

    /// A file's `name`: its path's last component, as `NSString` gives it (`File/name`), sliced from the path where
    /// it doesn't end in "/", so it copies no bytes.
    ///
    /// - Parameter path: The file's path, or `nil` without a file.
    /// - Returns: The name, or ``IndicatorValue/null`` without a file.
    static func name(ofPath path: String?) -> IndicatorValue {
        guard let path else { return .null }
        let bytes = path.utf8
        let slash = UInt8(ascii: "/")
        guard let last = bytes.last, last != slash else {
            return IndicatorValue((path as NSString).lastPathComponent)
        }
        guard let separator = bytes.lastIndex(of: slash) else { return .string(path[...]) }
        return .string(Substring(bytes[bytes.index(after: separator)...]))
    }
}
