//
//  SavedIndicatorSet.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import Combine
import OSLog


// MARK: - Saved indicator set
/// The Mac's one indicator set (Security Extension context): the file (``IndicatorFile``), compiled, and every capture
/// session that follows it.
///
/// Mac Monitor's capture and every `macmonitor stream`, `--no-mutes` included, follow it: each change is saved,
/// compiled, then handed to every follower, which applies it to its session (``CaptureSession/applyIndicators(_:)``).
/// Each event is stamped with what it matches, so a stream has nothing to be told. It's the same set for every user:
/// an indicator's severity, predicate, name and the rest but its view switches are Mac-wide.
///
/// **Requests** (``IndicatorRequest``) are read strictly. A list is answered at once, from a reply encoded once per
/// change. A change is checked against who may make it (``MuteAccess``) and refused while the set is read-only, Restore
/// Defaults included. The next set is checked (``IndicatorFile/validate(_:)``), compiled reusing every rule the current
/// one has by its text, so an add compiles only what it adds, checked again as compiled, and saved. Only then do the
/// followers get it, in the order they started following. Writers don't conflict: the last one wins, as with mutes.
/// An indicator that doesn't compile is kept, and every reply lists why (``IndicatorReply/problems``).
///
/// **Loading** (``load()``) is crash safe: a marker is kept while the saved file is read and compiled, and one found
/// at startup moves the file aside and starts from the shipped indicators. A missing or unreadable file starts from
/// them too, and is saved. A newer file is kept as it is, read-only, with the shipped indicators applied. Every
/// shipped indicator is compiled first, and one that doesn't compile is logged as a fault.
///
/// **Threading:** all state lives on ``queue``. Followers are called on it in change order and must hop to their
/// session's own queue. Nothing here ever waits on a session's queue, so a session may call ``follow(_:)``
/// synchronously from its own. A follower must never call back in synchronously.
public final class SavedIndicatorSet {
    /// Receives each new compiled set.
    public typealias Follower = (CompiledIndicators) -> Void

    /// The saved file.
    let store: RootFileStore
    /// The marker kept while the saved file is read and compiled.
    let loadingMarker: RootFileStore
    /// The indicators this build ships, which the set starts from and Restore Defaults brings back.
    let defaults: [Indicator]
    /// Them by identity, which each hit says it is, and whether this Mac edited it.
    let shipped: [UUID: Indicator]
    /// Serializes everything below.
    let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.indicators")
    /// The set as saved: its indicators, and the entries this build can't read, which are written back.
    var saved: SavedIndicators
    /// The set, compiled, as every follower runs it.
    var compiled: CompiledIndicators
    /// Whether the set can be changed. A file from a newer Mac Monitor can't be, Restore Defaults included.
    var state: SavedSetState = .writable
    /// Told to the user with every reply until the next change: the set was recovered or can't be changed.
    var notice: String?
    /// The shipped indicators the Security Extension can't run, from the startup self-test: none in a sound build.
    var defaultProblems: [CompiledIndicators.Problem] = []
    /// Has the set been loaded?
    var isLoaded = false
    /// The list reply as it stands, encoded for each access it was asked with, until the next change. Internal so a
    /// test can see a list answered from it.
    var listReplies: [MuteAccess: Data] = [:]
    /// Every capture session that follows the set.
    private lazy var followers = FollowerRegistry<Follower>(queue: queue)
    let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SavedIndicatorSet")

    /// - Parameters:
    ///   - directory: The directory holding the saved file: the Security Extension's own, unless a test passes one.
    ///   - owner: Who must own the directory and file: root, unless a test passes the user running it.
    ///   - defaults: The indicators this build ships, unless a test passes its own.
    public init(directory: URL = RootFileStore.systemDirectory, owner: uid_t = 0,
                defaults: [Indicator] = Indicator.defaults) {
        store = RootFileStore(directory: directory, owner: owner, layout: IndicatorFile.layout)
        loadingMarker = RootFileStore(directory: directory, owner: owner, layout: IndicatorFile.loadingLayout)
        self.defaults = defaults
        shipped = Indicator.byID(defaults)
        saved = SavedIndicators(defaults, defaults: defaults)
        compiled = CompiledIndicators([], defaults: shipped)
    }

    /// Read the saved set, creating it from the shipped indicators on first run. Does nothing once loaded.
    public func load() {
        queue.sync { loadIfNeeded() }
    }

    /// The compiled set now, and a subscription that hands each later one to `follower` until it's released. Atomic,
    /// so a session never misses a change between reading the set and following it.
    ///
    /// - Parameter follower: Receives each new compiled set, on ``queue``.
    /// - Returns: The set now, and the subscription, which stops the follower once it's released, on any thread.
    ///   Sets already handed to the follower may still be on their way to its session.
    public func follow(_ follower: @escaping Follower) -> (CompiledIndicators, AnyCancellable) {
        queue.sync {
            loadIfNeeded()
            return (compiled, followers.add(follower))
        }
    }

    /// How many capture sessions follow the set now. A released subscription stops counting once ``queue`` has run
    /// what was queued before this.
    var followerCount: Int {
        queue.sync { followers.count }
    }

    /// Answer a request from Mac Monitor or `macmonitor`.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``IndicatorRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log, such as "Mac Monitor (pid 123)".
    ///   - reply: Receives a JSON encoded ``IndicatorReply``, on ``queue``. It says what the caller may do, so Mac
    ///     Monitor can disable what it may not.
    public func handle(_ request: Data, access: MuteAccess, caller: String, reply: @escaping (Data) -> Void) {
        queue.async { [self] in reply(respond(to: request, access: access, caller: caller)) }
    }

    /// Wait for every request already handled to be answered and every change handed to the followers.
    func waitUntilIdle() {
        queue.sync {}
    }

    /// The work behind ``handle(_:access:caller:reply:)``. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - data: A JSON encoded ``IndicatorRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The encoded reply: for a list, the one cached since the last change.
    func respond(to data: Data, access: MuteAccess, caller: String) -> Data {
        loadIfNeeded()
        var answer: IndicatorReply
        do {
            let request = try IndicatorRequest.decode(data)
            if request.operation == .list {
                if let cached = listReplies[access] { return cached }
                answer = reply(.ok)
                answer.access = access
                let encoded = answer.encoded()
                listReplies[access] = encoded
                return encoded
            }
            answer = perform(request, access: access, caller: caller)
        } catch {
            answer = reply(error.status(), failure: error.description)
        }
        answer.access = access
        return answer.encoded()
    }

    /// Make a change. Call on ``queue``.
    ///
    /// 1. Refuse a caller that may only read (``MuteAccess/refusal(changing:)``), and every change while the set is
    ///    read-only or can't be kept.
    /// 2. Work out the next set and check it, refusing the request if it's past a limit.
    /// 3. Write nothing if nothing changes.
    /// 4. Compile it, reusing the current set's rules, and check it as compiled.
    /// 5. Save it. If that fails, nothing changes.
    /// 6. Hand it to every follower, and log it with the caller.
    ///
    /// - Parameters:
    ///   - request: The request, which isn't a list.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply, with the set as it stands.
    func perform(_ request: IndicatorRequest, access: MuteAccess, caller: String) -> IndicatorReply {
        loadIfNeeded()
        if let refusal = access.refusal(changing: "the indicators") {
            logger.error("""
                Refused \(request.operation.rawValue, privacy: .public) from \(caller, privacy: .public), which may \
                only read the indicators (\(access.rawValue, privacy: .public)).
                """)
            return reply(refusal.status, failure: refusal.problem)
        }
        switch state {
        case .readOnly:
            return reply(.readOnly, failure: """
                The indicators were saved by a newer Mac Monitor, so they can't be changed here. Update Mac Monitor \
                to change them.
                """)
        case .unavailable(let reason):
            return reply(.storageFailed, failure: reason)
        case .writable:
            break
        }
        let next: [Indicator], nextCompiled: CompiledIndicators
        do {
            next = try nextIndicators(for: request)
            try IndicatorFile.validate(next)
            guard !next.isIdentical(to: saved.indicators) else { return reply(.ok) }
            nextCompiled = CompiledIndicators(next, defaults: shipped, reusing: compiled)
            try IndicatorFile.validate(nextCompiled)
        } catch {
            return reply(.invalid, failure: "\(error)")
        }
        var nextSaved = saved
        nextSaved.indicators = next
        guard let bytes = IndicatorFile(nextSaved).encoded(), bytes.count <= IndicatorLimits.maxFileBytes else {
            return reply(.invalid, failure: "The indicators would be larger than \(store.maxSizeText) saved.")
        }
        do {
            try store.write(bytes)
        } catch {
            logger.fault("""
                Couldn't save the indicators \(caller, privacy: .public) asked for: \
                \(String(describing: error), privacy: .public)
                """)
            return reply(.storageFailed, failure: "The indicators couldn't be saved, so nothing changed. \(error)")
        }
        logChange(request.operation, by: caller, from: saved.indicators, to: next, fields: request.fields)
        replace(with: nextSaved, compiled: nextCompiled)
        return reply(.ok, changed: true)
    }

    /// Make a set the current one, and hand it to every follower. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - next: The set as saved.
    ///   - nextCompiled: The set, compiled.
    private func replace(with next: SavedIndicators, compiled nextCompiled: CompiledIndicators) {
        saved = next
        compiled = nextCompiled
        notice = nil
        listReplies = [:]
        followers.notify { $0(nextCompiled) }
    }

    /// The set a request asks for. Every indicator it brings is checked first (``IndicatorFile/validateIncoming(_:)``).
    ///
    /// - Parameter request: The request.
    /// - Returns: The next set, in order.
    /// - Throws: ``IndicatorFileError``, or ``IndicatorRequestProblem`` for an identity the set doesn't have.
    private func nextIndicators(for request: IndicatorRequest) throws -> [Indicator] {
        let indicators = saved.indicators
        switch request.operation {
        case .list:
            return indicators
        case .add:
            try IndicatorFile.validateIncoming(request.indicators)
            return IndicatorExchange.merge(request.indicators, into: indicators).indicators
        case .replace:
            try IndicatorFile.validateIncoming(request.indicators)
            return request.indicators
        case .remove:
            try checkKnown(request.ids)
            let removing = Set(request.ids)
            return indicators.filter { !removing.contains($0.id) }
        case .setEnabled:
            guard let enabled = request.enabled else {
                throw IndicatorRequestProblem("Say whether to turn the indicators on or off.")
            }
            try checkKnown(request.ids)
            let changing = Set(request.ids)
            return indicators.map { indicator in
                var indicator = indicator
                if changing.contains(indicator.id) { indicator.isEnabled = enabled }
                return indicator
            }
        case .update:
            return try updated(indicators, by: request)
        }
    }

    /// The set after an update: the named fields of each indicator the request brings taken into the one with its
    /// identity, in its place, and nothing else changed. What it makes is checked as the indicators an add brings
    /// are.
    ///
    /// - Parameters:
    ///   - indicators: The set now.
    ///   - request: The update.
    /// - Returns: The next set, in order.
    /// - Throws: ``IndicatorRequestProblem`` for no fields, an identity named twice or one the set doesn't have;
    ///   ``IndicatorFileError`` for an indicator the update leaves past a limit.
    private func updated(_ indicators: [Indicator], by request: IndicatorRequest) throws -> [Indicator] {
        guard !request.fields.isEmpty else { throw IndicatorRequestProblem("Name the fields to change.") }
        let ids = request.indicators.map(\.id)
        guard Set(ids).count == ids.count else { throw IndicatorRequestProblem("Name each indicator once.") }
        try checkKnown(ids)
        let incoming = Dictionary(uniqueKeysWithValues: request.indicators.map { ($0.id, $0) })
        let next = indicators.map { indicator in
            guard let edit = incoming[indicator.id] else { return indicator }
            var indicator = indicator
            indicator.take(request.fields, from: edit)
            return indicator
        }
        try IndicatorFile.validateIncoming(next.filter { incoming[$0.id] != nil })
        return next
    }

    /// - Parameter ids: Identities a request names.
    /// - Throws: ``IndicatorRequestProblem`` when it names none, or one the set doesn't have.
    private func checkKnown(_ ids: [UUID]) throws {
        guard !ids.isEmpty else { throw IndicatorRequestProblem("Name the indicators by their identities.") }
        let known = Set(saved.indicators.map(\.id))
        let unknown = ids.filter { !known.contains($0) }
        guard unknown.isEmpty else {
            let list = unknown.map(\.uuidString).joined(separator: ", ")
            throw IndicatorRequestProblem("No indicator has the identity \(list).")
        }
    }

    /// A reply with the set as it stands.
    ///
    /// - Parameters:
    ///   - status: How the request went.
    ///   - changed: Did the set change?
    ///   - failure: Why the request was refused or invalid.
    /// - Returns: The reply, with no access: the caller's is added to it. It says whether the set is read-only.
    func reply(_ status: IndicatorReply.Status, changed: Bool = false, failure: String? = nil) -> IndicatorReply {
        IndicatorReply(status: status, changed: changed, indicators: saved.indicators,
                       problems: compiled.problems.map { IndicatorReply.Problem(id: $0.id, reason: $0.reason) },
                       failure: failure, notice: notice, readOnly: state != .writable)
    }
}


// MARK: - Request problems
/// Why a request can't be done, beyond what ``IndicatorFileError`` says: such as an identity the set doesn't have.
struct IndicatorRequestProblem: Error, CustomStringConvertible {
    /// The problem, as a sentence.
    let description: String

    /// - Parameter description: The problem, as a sentence.
    init(_ description: String) {
        self.description = description
    }
}
