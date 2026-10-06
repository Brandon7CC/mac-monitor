//
//  SyntheticCorpus.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Synthetic corpus
/// One synthetic event for every event type the schema describes: full variants (one per union arm and per value that
/// picks an encoder's branch) and one empty variant each.
enum SyntheticCorpus {
    /// A synthetic event, and what it is.
    struct Record {
        /// The event's name and variant: `exec (full)`.
        let label: String
        /// How it was filled.
        let variant: SyntheticVariant
        /// The event.
        let message: Message
    }
    
    /// Every record, for every event type of ``TelemetrySchemaSource/events``.
    ///
    /// - Returns: The records, event by event.
    /// - Throws: The error making up an event: a type the decoder can't make up, or an enum without an arm.
    static func records() throws -> [Record] {
        try TelemetrySchemaSource.events.flatMap { event in
            try variants(of: event).map { variant in
                let label = "\(event.name) (\(variant.name))"
                do {
                    return Record(label: label, variant: variant,
                                  message: try SyntheticDecoder(variant).make(Message.self))
                } catch {
                    throw SyntheticCorpusError(label: label, underlying: error)
                }
            }
        }
    }
    
    /// An event's variants.
    ///
    /// - Parameter event: The event type.
    /// - Returns: The full variants, then the empty one.
    static func variants(of event: SchemaEvent) -> [SyntheticVariant] {
        let arms = ["EventType": event.name, "FileDestination": "existing_file", "FilePathUnion": "file"]
        let integers = ["event_type": event.number, "result_type": Int(ES_RESULT_TYPE_AUTH.rawValue),
                        "destination_type": Int(ES_DESTINATION_TYPE_EXISTING_FILE.rawValue),
                        "file_type": Int(ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE.rawValue),
                        "member_type": Int(ES_OD_MEMBER_TYPE_USER_NAME.rawValue)]
        /// An auth result has no flags: the flags variant takes the other arm.
        let unflagged = "AuthResult.flags"
        let full = SyntheticVariant(name: "full", full: true, arms: arms, integers: integers, absent: [unflagged])
        /// A full variant with other arms, integers or keys left out.
        func variant(_ name: String, arms more: [String: String] = [:], _ chosen: [String: Int] = [:],
                     absent: Set<String> = [unflagged]) -> SyntheticVariant {
            SyntheticVariant(name: name, full: true, arms: arms.merging(more) { $1 },
                             integers: integers.merging(chosen) { $1 }, absent: absent)
        }
        var all = [full]
        switch event.type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            all.append(variant("descriptor without pipe", absent: [unflagged, "FileDescriptor.pipe"]))
            all.append(variant("launched-by parent without process",
                               absent: [unflagged, "LaunchedByParent.audit_token", "LaunchedByParent.pid",
                                        "LaunchedByParent.path", "LaunchedByParent.launchd_job"]))
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            /// eslogger's `state` is `null`: the decoder falls back to it without `state_base64`.
            all.append(variant("state without bytes",
                               absent: [unflagged, "ThreadState.state_base64", "ThreadState.state"]))
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            all.append(variant("flags", ["result_type": Int(ES_RESULT_TYPE_FLAGS.rawValue)],
                               absent: ["AuthResult.auth", "AuthResult.auth_human"]))
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            /// A parent at message version 10 whose path is NULL.
            all.append(variant("parent without path", absent: [unflagged, "IOKitOpenEvent.parent_path"]))
            /// A parent at message version 10 that Mac Monitor before 2.2.0 left out, registry ID and all.
            all.append(variant("parent unrecorded", absent: [unflagged, "IOKitOpenEvent.parent_path",
                                                             "IOKitOpenEvent.parent_registry_id"]))
        case ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME:
            /// A rename's new path has no mode.
            let mode: Set<String> = event.type == ES_EVENT_TYPE_NOTIFY_RENAME
                ? [unflagged, "NewPath.mode"] : [unflagged]
            all.append(variant("new_path", arms: ["FileDestination": "new_path"],
                               ["destination_type": Int(ES_DESTINATION_TYPE_NEW_PATH.rawValue)], absent: mode))
            all.append(variant("unknown destination", arms: ["FileDestination": "unknown"], ["destination_type": 2]))
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
            let path = ["file_type": Int(ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH.rawValue)]
            all.append(variant("path", arms: ["FilePathUnion": "file_path"], path))
            /// A path arm whose path is NULL, which eslogger writes as `"file": null`.
            all.append(variant("null path", arms: ["FilePathUnion": "unknown"], path))
            all.append(variant("unknown file", arms: ["FilePathUnion": "unknown"], ["file_type": 2]))
            /// Signing information without IDs, such as an ad hoc signature's: eslogger writes them as `null`.
            all.append(variant("signing info without IDs",
                               absent: [unflagged, "SignedFileInfo.signing_id", "SignedFileInfo.team_id"]))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
            all.append(variant("user UUID", ["member_type": Int(ES_OD_MEMBER_TYPE_USER_UUID.rawValue)]))
            all.append(variant("group UUID", ["member_type": Int(ES_OD_MEMBER_TYPE_GROUP_UUID.rawValue)]))
            all.append(variant("member without value", absent: [unflagged, "OpenDirectoryMember.member_value"]))
        default:
            break
        }
        all.append(SyntheticVariant(name: "empty", full: false, arms: arms, integers: integers))
        precondition(all.allSatisfy { $0.absent.allSatisfy { $0.contains(".") } }, "Name absent keys as Type.key")
        return all.enumerated().map { index, variant in
            var spread = variant
            spread.index = index
            return spread
        }
    }
    
    /// Optional fields Mac Monitor derives that are `nil` for some events however full they are: `Type.key`.
    static let derivedNils: Set<String> = ["Message.target_path"]
    
    /// The places a full variant's event has no value: every optional `nil` and every empty array, but for the keys
    /// the variant leaves out on purpose. None means the decoder filled every field, new ones included.
    ///
    /// - Parameters:
    ///   - value: The event, or a value in it.
    ///   - path: The value's path.
    ///   - field: The value's key, as `Type.key` for its type's.
    ///   - absent: The keys left out on purpose.
    /// - Returns: The paths of the values missing.
    static func gaps(in value: Any, at path: String = "", field: (owner: String, key: String) = ("", ""),
                     absent: Set<String>) -> [String] {
        let mirror = Mirror(reflecting: value)
        switch mirror.displayStyle {
        case .optional:
            guard let wrapped = mirror.children.first?.value else {
                let qualified = "\(field.owner).\(field.key)"
                let allowed = absent.contains(qualified) || absent.contains("*.\(field.key)")
                    || derivedNils.contains(qualified)
                return allowed ? [] : [path]
            }
            return gaps(in: wrapped, at: path, field: field, absent: absent)
        case .collection:
            guard !mirror.children.isEmpty else { return ["\(path) (empty)"] }
            return mirror.children.flatMap { gaps(in: $0.value, at: "\(path)[]", field: field, absent: absent) }
        case .struct, .class, .enum:
            let owner = String(describing: mirror.subjectType)
            return mirror.children.flatMap { child in
                let key = child.label ?? "?"
                return gaps(in: child.value, at: path.isEmpty ? key : "\(path).\(key)", field: (owner, key),
                            absent: absent)
            }
        default:
            return []
        }
    }
}


/// A synthetic event that couldn't be made up.
struct SyntheticCorpusError: Error, CustomStringConvertible {
    /// The event and variant.
    let label: String
    /// Why.
    let underlying: Error
    
    /// The event, and the decoder's error with its path. An enum with associated values that no arm names says so.
    var description: String {
        guard let decoding = underlying as? DecodingError, let context = decoding.context else {
            return "\(label): \(underlying)"
        }
        let path = context.codingPath.map(\.stringValue).joined(separator: ".")
        guard case .typeMismatch(let type, _) = decoding, context.debugDescription.hasPrefix("Invalid number of keys")
        else {
            return "\(label): \(path): \(context.debugDescription)"
        }
        return "\(label): \(path): \(type) is an enum with associated values: name the case it decodes as in the "
            + "arms of SyntheticCorpus.variants(of:)."
    }
}
