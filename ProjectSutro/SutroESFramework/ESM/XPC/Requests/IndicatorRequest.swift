//
//  IndicatorRequest.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Request
/// A request about the Mac's indicator set, from Mac Monitor or `macmonitor`, as JSON over XPC: the one set the
/// Security Extension keeps (``SavedIndicatorSet``) and stamps every captured event with.
///
/// Import and Export happen in the caller: it reads a file into indicators and sends `.add` or `.replace`, and writes
/// the indicators of a reply to a file. The Security Extension only ever reads indicators, never a file or a path to
/// one. Severity, like the rest of an indicator but its view switches, is part of the detection, so it travels here.
public struct IndicatorRequest: XPCRequest, Equatable {
    /// The version of requests and replies this Mac Monitor sends and understands.
    public static let currentVersion: Int = 1
    /// The largest request: as large as the saved file.
    public static let maximumSize: Int = IndicatorLimits.maxFileBytes
    /// What the request is, for messages.
    public static let noun = "indicator request"

    /// What to do with the indicator set.
    public enum Operation: String, Codable, CaseIterable, Sendable {
        /// Reply with the set.
        case list
        /// Merge the request's indicators into the set (``IndicatorExchange/merge(_:into:)``): one with an identity
        /// the set has replaces it in its place, and the rest are added at the end. It's how an import, a new
        /// indicator, a Duplicate and the 3.0 import offer arrive.
        case add
        /// Remove the indicators ``IndicatorRequest/ids`` names.
        case remove
        /// Turn the indicators ``IndicatorRequest/ids`` names on or off, as ``IndicatorRequest/enabled`` says.
        case setEnabled
        /// Make the set exactly the request's indicators.
        case replace
        /// Make the set the indicators this Security Extension ships, whoever asks: Restore Defaults. The asker
        /// sends none of its own, so a Mac Monitor of another build can't put its list in their place, which would
        /// remove the indicators only this build ships and keep its older rules for the rest as if they were edits.
        case reset
        /// Change the named fields (``IndicatorRequest/fields``) of indicators the set has, by identity, keeping
        /// their place, switch and views. One the set doesn't have is refused, never added, and fields not named
        /// stay as the set has them, so an edit undoes no other writer's change.
        case update
    }

    /// The request's version.
    public var version: Int
    /// What to do.
    public var operation: Operation
    /// The indicators to add, or to replace the set with.
    public var indicators: [Indicator]
    /// The indicators to remove, or turn on or off, by identity.
    public var ids: [UUID]
    /// On or off, for ``Operation/setEnabled``.
    public var enabled: Bool?
    /// The fields an ``Operation/update`` takes from each of the request's indicators.
    public var fields: [Indicator.EditableField]

    /// - Parameters:
    ///   - operation: What to do.
    ///   - indicators: The indicators to add, or to replace the set with.
    ///   - ids: The indicators to remove, or turn on or off.
    ///   - enabled: On or off, for ``Operation/setEnabled``.
    ///   - fields: The fields to change, for ``Operation/update``.
    public init(_ operation: Operation, indicators: [Indicator] = [], ids: [UUID] = [], enabled: Bool? = nil,
                fields: [Indicator.EditableField] = []) {
        version = Self.currentVersion
        self.operation = operation
        self.indicators = indicators
        self.ids = ids
        self.enabled = enabled
        self.fields = fields
    }

    /// Read the version, then the operation as a name, so a newer request is reported as unsupported rather than as
    /// malformed. Every indicator has to decode (``Indicator/init(from:)``), within its field limits. Fields are read
    /// by name, so one a newer Mac Monitor added is unsupported too.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: ``XPCRequestError`` for a version below 1 or newer than this build's, an unknown operation or field,
    ///   or a `DecodingError`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        (version, operation) = try Self.header(of: container, version: .version, name: .operation)
        indicators = try container.decodeIfPresent([Indicator].self, forKey: .indicators) ?? []
        ids = try container.decodeIfPresent([UUID].self, forKey: .ids) ?? []
        enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled)
        fields = try (container.decodeIfPresent([String].self, forKey: .fields) ?? []).map { name in
            guard let field = Indicator.EditableField(rawValue: name) else {
                throw XPCRequestError.unsupported("This Security Extension doesn't know the field “\(name)”.")
            }
            return field
        }
    }

    /// Why some JSON isn't an indicator request: where, and what.
    ///
    /// - Parameter error: The decoding error.
    /// - Returns: Such as ": “indicators.2.name” is missing", or an indicator's own reason for a field past its
    ///   limit.
    public static func invalidReason(_ error: Error) -> String {
        guard case DecodingError.dataCorrupted(let context)? = error as? DecodingError,
              !context.codingPath.isEmpty else { return ": \(MuteFile.reason(error))" }
        let location = context.codingPath.map { $0.intValue.map(String.init) ?? $0.stringValue }
            .joined(separator: ".")
        return ": “\(location)”: \(context.debugDescription)"
    }
}


// MARK: - Reply
/// The Security Extension's answer to an ``IndicatorRequest``: always the set as it stands after the request.
public struct IndicatorReply: XPCReply, Equatable {
    /// How the request went: as for the saved mute set. ``MuteReply/Status/readOnly`` here means a newer Mac Monitor
    /// wrote the set, and nothing may change it, Restore Defaults included.
    public typealias Status = MuteReply.Status

    /// An indicator the Security Extension keeps but can't run, and why.
    public struct Problem: Codable, Equatable, Sendable {
        /// The indicator's identity.
        public var id: UUID
        /// Why, as Settings shows it after "Not run by the Security Extension: ".
        public var reason: String

        /// - Parameters:
        ///   - id: The indicator's identity.
        ///   - reason: Why it can't run.
        public init(id: UUID, reason: String) {
            self.id = id
            self.reason = reason
        }
    }

    /// The reply's version.
    public var version: Int = IndicatorRequest.currentVersion
    /// How the request went.
    public var status: Status
    /// Did the set change?
    public var changed: Bool = false
    /// The set after the request, in order, each as the Security Extension resolved it.
    public var indicators: [Indicator]
    /// The indicators in the set the Security Extension can't run, in the set's order.
    public var problems: [Problem] = []
    /// Why the request was refused or invalid, as a sentence.
    public var failure: String?
    /// Something to tell the user about the set: it was recovered from a damaged file, or is read-only.
    public var notice: String?
    /// What the caller may do with the set, or `nil` if the Security Extension didn't say (or said something this
    /// build doesn't know).
    public var access: MuteAccess?
    /// Can nobody change the set? A newer Mac Monitor saved it, or it can't be kept: every change is refused, Restore
    /// Defaults included, whatever ``access`` says.
    public var readOnly: Bool = false

    /// - Parameters:
    ///   - status: How the request went.
    ///   - changed: Did the set change?
    ///   - indicators: The set after the request.
    ///   - problems: The indicators the Security Extension can't run.
    ///   - failure: Why the request was refused or invalid.
    ///   - notice: Something to tell the user about the set.
    ///   - access: What the caller may do.
    ///   - readOnly: Can nobody change the set?
    public init(status: Status, changed: Bool = false, indicators: [Indicator], problems: [Problem] = [],
                failure: String? = nil, notice: String? = nil, access: MuteAccess? = nil, readOnly: Bool = false) {
        self.status = status
        self.changed = changed
        self.indicators = indicators
        self.problems = problems
        self.failure = failure
        self.notice = notice
        self.access = access
        self.readOnly = readOnly
    }
}


extension IndicatorReply {
    /// Everything but the version and status may be missing, an unknown status reads as ``Status/unsupported``, an
    /// unknown access as none, a missing `readOnly` as `false`, and an indicator or problem that doesn't read is left
    /// out, so a newer Security Extension's reply still reads.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing version or status.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        status = try container.decode(Status.self, forKey: .status)
        changed = (try? container.decodeIfPresent(Bool.self, forKey: .changed)) ?? false
        indicators = ((try? container.decodeIfPresent([Lossy<Indicator>].self, forKey: .indicators)) ?? [])
            .compactMap(\.value)
        problems = ((try? container.decodeIfPresent([Lossy<Problem>].self, forKey: .problems)) ?? [])
            .compactMap(\.value)
        failure = try? container.decodeIfPresent(String.self, forKey: .failure)
        notice = try? container.decodeIfPresent(String.self, forKey: .notice)
        access = (try? container.decodeIfPresent(String.self, forKey: .access)).flatMap { $0 }
            .flatMap(MuteAccess.init(rawValue:))
        readOnly = (try? container.decodeIfPresent(Bool.self, forKey: .readOnly)) ?? false
    }
}


// MARK: - Lossy elements
/// An array element that's kept when it decodes and left out when it doesn't, so one a newer peer added doesn't fail
/// the whole array.
struct Lossy<Value: Decodable>: Decodable {
    /// The element, or `nil` when it didn't decode.
    let value: Value?

    /// - Parameter decoder: The element's decoder.
    init(from decoder: Decoder) {
        value = try? Value(from: decoder)
    }
}
