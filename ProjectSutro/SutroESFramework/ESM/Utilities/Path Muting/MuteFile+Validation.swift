//
//  MuteFile+Validation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Reading mutes
extension MuteFile {
    /// What reading entries does with what it can't use.
    public enum Strictness: Sendable {
        /// Refuse an invalid entry or an unknown event name: requests to the Security Extension.
        case strict
        /// Leave out event names Mac Monitor doesn't know, which a newer one may have written, with a warning, and
        /// refuse an invalid entry: the saved file.
        case saved
        /// Leave out unknown event names and invalid entries, each with a warning: a file being imported.
        case lenient
    }
    
    /// The list this file's mutes describe.
    ///
    /// - Parameter strictness: What to do with what can't be used.
    /// - Returns: The list, merged by path and type, and a sentence for each thing left out or likely to surprise.
    /// - Throws: ``MuteFileError/invalidMute(index:reason:)`` for an entry that can't be used (unless lenient, or
    ///   for the saved file an entry naming only events a newer Mac Monitor knows), ``MuteFileError/tooManyMutes(_:)``.
    public func list(_ strictness: Strictness) throws -> (list: MuteList, warnings: [String]) {
        try Self.list(from: mutes, strictness)
    }
    
    /// The list some entries describe.
    ///
    /// - Parameters:
    ///   - entries: The entries.
    ///   - strictness: What to do with what can't be used.
    /// - Returns: The list, merged by path and type, and a sentence for each thing left out or likely to surprise.
    ///   The saved file's own entries never warn about their paths.
    /// - Throws: ``MuteFileError/invalidMute(index:reason:)`` for an entry that can't be used (unless lenient, or
    ///   for the saved file an entry naming only events a newer Mac Monitor knows), ``MuteFileError/tooManyMutes(_:)``.
    public static func list(from entries: [Entry], _ strictness: Strictness) throws
        -> (list: MuteList, warnings: [String]) {
        var list = MuteList()
        var warnings: [String] = []
        for (index, entry) in entries.enumerated() {
            do {
                let checked = try entry.validated(droppingUnknownEvents: strictness != .strict)
                warnings += checked.warnings.map { "\(entry.label): \($0)" }
                if strictness != .saved, let advice = entry.resolvedPathAdvice { warnings.append(advice) }
                list.add(checked.mute)
            } catch let problem as EntryProblem {
                /// The saved file only leaves out what a newer Mac Monitor wrote; anything else means it's damaged.
                guard strictness == .lenient || problem.isFromNewerMacMonitor else {
                    throw MuteFileError.invalidMute(index: index, reason: "\(entry.label) \(problem.reason)")
                }
                warnings.append("Left out \(entry.label): it \(problem.reason).")
            }
        }
        guard list.count <= MuteLimits.maxMutes else { throw MuteFileError.tooManyMutes(list.count) }
        return (list, warnings)
    }
}


// MARK: - Validating an entry
extension MuteFile.Entry {
    /// The mute types, by their `ES_MUTE_PATH_TYPE_*` names.
    private static let types: [String: es_mute_path_type_t] = Dictionary(uniqueKeysWithValues: [
        ES_MUTE_PATH_TYPE_PREFIX, ES_MUTE_PATH_TYPE_LITERAL, ES_MUTE_PATH_TYPE_TARGET_PREFIX,
        ES_MUTE_PATH_TYPE_TARGET_LITERAL
    ].map { (getMuteCaseString(muteType: $0), $0) })
    
    /// Paths Endpoint Security only sees through `/private`, since it matches resolved paths (`ESTypes.h`).
    private static let unresolvedRoots = ["/tmp", "/var", "/etc"]
    
    /// The entry's mute type, if the name is one of Endpoint Security's four.
    var muteType: es_mute_path_type_t? { Self.types[type] }
    
    /// The entry as a mute Endpoint Security and Mac Monitor's clients can use.
    ///
    /// 1. The type must be one of the four `ES_MUTE_PATH_TYPE_*` names; files never use short names.
    /// 2. The path must be absolute, without a NUL, and at most ``MuteLimits/maxPathBytes``.
    /// 3. At most ``MuteLimits/maxEventsPerMute`` event names, each counted once. Unknown event names are refused, or
    ///    left out with a warning. An entry that names only unknown events is refused either way: no events would mean
    ///    every event.
    /// 4. AUTH events are left out with a warning: Mac Monitor's clients subscribe only to NOTIFY events.
    /// 5. For a target type, events Endpoint Security can't mute by target path (``allowedTargetPathEvents``) are
    ///    left out with a warning, since `es_mute_path_events` fails if none of them can be.
    ///
    /// - Parameter droppingUnknownEvents: Leave out unknown event names rather than refusing the entry.
    /// - Returns: The mute, and what was left out of it.
    /// - Throws: ``EntryProblem`` when the entry can't be used.
    func validated(droppingUnknownEvents: Bool) throws -> (mute: PathMute, warnings: [String]) {
        guard let type = muteType else { throw EntryProblem("has an unknown mute type") }
        guard !path.isEmpty else { throw EntryProblem("has an empty path") }
        guard path.hasPrefix("/") else { throw EntryProblem("isn't an absolute path") }
        guard !path.contains("\0") else { throw EntryProblem("has a NUL character in its path") }
        guard path.utf8.count <= MuteLimits.maxPathBytes else {
            throw EntryProblem("has a path longer than \(MuteLimits.maxPathBytes) bytes")
        }
        guard !events.isEmpty else { return (PathMute(path: path, type: type), []) }
        guard events.count <= MuteLimits.maxEventsPerMute else {
            throw EntryProblem("names more than \(MuteLimits.maxEventsPerMute) events")
        }
        
        /// Each name once, in order, so every check below is linear.
        var seen = Set<String>()
        let names = events.filter { seen.insert($0).inserted }
        var warnings: [String] = []
        let unknown = names.filter { eventStringToType(from: $0) == ES_EVENT_TYPE_LAST }
        if !unknown.isEmpty {
            guard droppingUnknownEvents else {
                throw EntryProblem("names events Mac Monitor doesn't know (\(Self.list(unknown)))")
            }
            guard unknown.count < names.count else {
                throw EntryProblem("names only events Mac Monitor doesn't know (\(Self.list(unknown)))",
                                   isFromNewerMacMonitor: true)
            }
            warnings.append("left out events Mac Monitor doesn't know (\(Self.list(unknown))).")
        }
        let known = names.filter { eventStringToType(from: $0) != ES_EVENT_TYPE_LAST }
        let auth = known.filter(Self.isAuth)
        let notify = known.filter { !Self.isAuth($0) }
        guard !notify.isEmpty else { throw EntryProblem("names only AUTH events, which Mac Monitor never receives") }
        if !auth.isEmpty {
            warnings.append("left out AUTH events (\(Self.list(auth))), which Mac Monitor never receives.")
        }
        var kept = notify.map { eventStringToType(from: $0) }
        if type == ES_MUTE_PATH_TYPE_TARGET_PREFIX || type == ES_MUTE_PATH_TYPE_TARGET_LITERAL {
            let untargetable = kept.filter { !allowedTargetPathEvents.contains($0) }
            kept = kept.filter { allowedTargetPathEvents.contains($0) }
            guard !kept.isEmpty else { throw EntryProblem("names no event Endpoint Security can mute by target path") }
            if !untargetable.isEmpty {
                let names = untargetable.map { eventTypeToString(from: $0) }
                warnings.append("left out events Endpoint Security can't mute by target path (\(Self.list(names))).")
            }
        }
        return (PathMute(path: path, type: type, events: kept), warnings)
    }
    
    /// A warning for a path Endpoint Security never matches as written, such as `/tmp/x` for `/private/tmp/x`.
    var resolvedPathAdvice: String? {
        guard let root = Self.unresolvedRoots.first(where: { path == $0 || path.hasPrefix($0 + "/") }) else {
            return nil
        }
        return """
            \(label): Endpoint Security matches resolved paths, so this never matches. Use \
            “/private\(root)\(path.dropFirst(root.count))”.
            """
    }
    
    /// Is an event name an AUTH event's?
    ///
    /// - Parameter name: An `ES_EVENT_TYPE_*` name.
    /// - Returns: `true` for `ES_EVENT_TYPE_AUTH_*`.
    private static func isAuth(_ name: String) -> Bool {
        name.hasPrefix("ES_EVENT_TYPE_AUTH_")
    }
    
    /// Names for a message, deduplicated in their order.
    ///
    /// - Parameter names: The names.
    /// - Returns: The names, comma separated.
    private static func list(_ names: [String]) -> String {
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }.joined(separator: ", ")
    }
}


// MARK: - Entry problems
/// Why an entry can't be used, as the rest of a sentence about it ("isn't an absolute path").
struct EntryProblem: Error, Equatable {
    /// The reason, after the entry's label.
    let reason: String
    /// Only names events this Mac Monitor doesn't know, as a newer one may have saved.
    let isFromNewerMacMonitor: Bool
    
    /// - Parameters:
    ///   - reason: The reason, after the entry's label.
    ///   - isFromNewerMacMonitor: Only names events this Mac Monitor doesn't know.
    init(_ reason: String, isFromNewerMacMonitor: Bool = false) {
        self.reason = reason
        self.isFromNewerMacMonitor = isFromNewerMacMonitor
    }
}
