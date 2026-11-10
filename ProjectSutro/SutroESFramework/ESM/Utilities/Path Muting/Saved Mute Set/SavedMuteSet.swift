//
//  SavedMuteSet.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import Combine
import OSLog


// MARK: - Saved mute set
/// The one saved mute set (Security Extension context): the file, and every capture session that follows it.
///
/// Mac Monitor and every `macmonitor stream` without `--no-mutes` follow it: each change is saved, then handed to
/// every follower, which applies it to its session (``CaptureSession/applyMutes(_:)``). Each follower also learns who
/// changed the set and how (``MuteSetChange``), so a stream can say so.
///
/// **Upgrades:** a saved set from an earlier default set revision that no one has changed becomes the current default
/// set when it loads, unless the user declined that revision. One someone has changed is kept, and every reply offers
/// the merge (``MuteSetUpdate``) until a ``MuteRequest/Operation/update`` or a Reset takes it in (``MuteSetUpgrade``).
/// A ``MuteRequest/Operation/decline`` is saved with the set, so it holds for every user and for the CLI.
///
/// **Threading:** all state lives on ``queue``. Followers are called on it in change order and must hop to their
/// session's own queue. Nothing here ever waits on a session's queue, so a session may call ``follow(_:)``
/// synchronously from its own. A follower must never call back in synchronously.
public final class SavedMuteSet {
    /// Receives each new saved set, and who changed it how.
    public typealias Follower = (MuteList, MuteSetChange) -> Void
    
    let store: MuteStore
    /// Who's logged in at the console: the default set mutes their home folder's caches.
    private let consoleUser: () -> ConsoleUser?
    /// Serializes everything below.
    let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.mutes")
    var list = MuteList()
    /// The default set revision ``list`` was last brought up to (``MuteSet/revisions``).
    var defaultsRevision = MuteSet.currentRevision
    /// A newer default set revision the user declined, saved with the set.
    var declinedRevision: Int?
    /// The saved set with a newer default set merged in, and what that changes, while it hasn't been taken in.
    var pendingUpdate: (list: MuteList, update: MuteSetUpdate)?
    /// The newer default set applied by itself when the set loaded, said with every reply until the next change.
    var appliedUpdate: MuteSetUpdate?
    /// Whether the saved set can be changed. A file from a newer Mac Monitor may only be overwritten by a Reset.
    private(set) var state: SavedSetState = .writable
    /// Told to the user with every reply until the next change: the set was recovered, can't be changed, or leaves
    /// out the per-user mutes because no one was logged in when it was made.
    var notice: String?
    private var isLoaded = false
    /// Every capture session that follows the set.
    private lazy var followers = FollowerRegistry<Follower>(queue: queue)
    let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SavedMuteSet")
    
    /// - Parameters:
    ///   - store: Where the set is kept.
    ///   - consoleUser: Who's logged in at the console when the default set is made (the first run, a damaged file,
    ///     Reset): the system's answer, unless a test passes its own.
    public init(store: MuteStore = MuteStore(), consoleUser: @escaping () -> ConsoleUser? = { ConsoleUser.current() }) {
        self.store = store
        self.consoleUser = consoleUser
    }
    
    /// Read the saved set, creating it from Mac Monitor's default set on first run. Does nothing once loaded.
    public func load() {
        queue.sync { loadIfNeeded() }
    }
    
    /// The current set, and a subscription that hands each later change to `follower` until it's released. Atomic,
    /// so a session never misses a change between reading the set and following it.
    ///
    /// - Parameter follower: Receives each new set and who changed it how, on ``queue``.
    /// - Returns: The set now, and the subscription, which stops the follower once it's released, on any thread.
    ///   Changes already handed to the follower may still be on their way to its session.
    public func follow(_ follower: @escaping Follower) -> (MuteList, AnyCancellable) {
        queue.sync {
            loadIfNeeded()
            return (list, followers.add(follower))
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
    ///   - request: A JSON encoded ``MuteRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log, such as "Mac Monitor (pid 123)".
    ///   - reply: Receives a JSON encoded ``MuteReply``, on ``queue``. It says what the caller may do, so Mac Monitor
    ///     can disable what it may not.
    public func handle(_ request: Data, access: MuteAccess, caller: String, reply: @escaping (Data) -> Void) {
        queue.async { [self] in
            var answer = perform(request, access: access, caller: caller)
            answer.access = access
            reply(answer.encoded())
        }
    }
    
    /// The work behind ``handle(_:access:caller:reply:)``. Call on ``queue``.
    ///
    /// 1. Read the request. A list is answered as is.
    /// 2. Refuse a change from a caller that may only read (``MuteAccess/refusal``), and any change but Reset to a
    ///    newer file.
    /// 3. Work out the new set, refusing the request if any of its mutes can't be used.
    /// 4. Write nothing if nothing changes. A Reset with no one logged in still says what it leaves out.
    /// 5. Save it. If that fails, nothing changes.
    /// 6. Hand it to every follower. The notice is now what a Reset left out, if anything, as on the first run.
    ///
    /// - Parameters:
    ///   - data: A JSON encoded ``MuteRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply, with the set as it stands.
    func perform(_ data: Data, access: MuteAccess, caller: String) -> MuteReply {
        loadIfNeeded()
        let request: MuteRequest
        do {
            request = try MuteRequest.decode(data)
        } catch {
            return reply(error.status(), problems: [error.description])
        }
        guard request.operation != .list else { return reply(.ok) }
        if let refusal = access.refusal {
            logger.error("""
                Refused \(request.operation.rawValue, privacy: .public) from \(caller, privacy: .public), which may \
                only read the saved mute set (\(access.rawValue, privacy: .public)).
                """)
            return reply(refusal.status, problems: [refusal.problem])
        }
        switch state {
        case .readOnly where request.operation != .reset:
            return reply(.readOnly, problems: [
                "The saved mute set was written by a newer Mac Monitor. It can only be reset to the default set here."
            ])
        case .unavailable(let reason):
            return reply(.storageFailed, problems: [reason])
        case .writable, .readOnly:
            break
        }
        if request.operation == .decline { return decline(by: caller) }
        let next: MuteList, warnings: [String], leftOut: String?
        do {
            (next, warnings, leftOut) = try nextList(for: request)
        } catch {
            return reply(.invalid, problems: ["\(error)"])
        }
        guard next != list || state != .writable else {
            notice = leftOut ?? notice
            return reply(.ok, problems: warnings)
        }
        /// Reset and update bring the set up to the current default set, with nothing left to decline. Other changes
        /// keep its revision and what was declined.
        let isCurrent = [.reset, .update].contains(request.operation)
        let revision = isCurrent ? MuteSet.currentRevision : defaultsRevision
        let declined = isCurrent ? nil : declinedRevision
        do {
            try store.save(next, defaultsRevision: revision, declinedRevision: declined)
        } catch {
            logger.fault("""
                Couldn't save the mute set \(caller, privacy: .public) asked for: \
                \(String(describing: error), privacy: .public)
                """)
            return reply(.storageFailed, problems: [
                "The saved mute set couldn't be written, so nothing changed. \(error)"
            ])
        }
        let difference = list.difference(to: next)
        logChange(request.operation, by: caller, difference, from: list, to: next)
        list = next
        defaultsRevision = revision
        declinedRevision = declined
        state = .writable
        notice = leftOut
        appliedUpdate = nil
        refreshUpdate()
        let change = MuteSetChange(by: caller, difference, mutes: next.count)
        followers.notify { $0(next, change) }
        return reply(.ok, changed: true, problems: warnings)
    }
    
    /// The set a request asks for. Every mute must be usable (``MuteFile/Strictness/strict``).
    ///
    /// - Parameter request: The request.
    /// - Returns: The new set, what was left out of the request's mutes, and for a Reset with no one logged in, what
    ///   the default set leaves out, as the notice.
    /// - Throws: ``MuteFileError``, or ``MuteListError`` for a remove that narrows a mute of every event.
    private func nextList(for request: MuteRequest) throws -> (MuteList, [String], String?) {
        switch request.operation {
        case .list:
            return (list, [], nil)
        case .add:
            let (adding, warnings) = try MuteFile.list(from: request.mutes, .strict)
            var next = list
            next.add(contentsOf: adding)
            guard next.count <= MuteLimits.maxMutes else { throw MuteFileError.tooManyMutes(next.count) }
            return (next, warnings, nil)
        case .remove:
            var next = list
            for (index, entry) in request.mutes.enumerated() {
                do {
                    try next.remove(entry.validated(droppingUnknownEvents: false).mute)
                } catch let problem as EntryProblem {
                    throw MuteFileError.invalidMute(index: index, reason: "\(entry.label) \(problem.reason)")
                }
            }
            return (next, [], nil)
        case .replace:
            let (next, warnings) = try MuteFile.list(from: request.mutes, .strict)
            return (next, warnings, nil)
        case .reset:
            let (next, leftOut) = defaultSet()
            return (next, [], leftOut)
        case .update:
            return (pendingUpdate?.list ?? list, [], nil)
        case .decline:
            return (list, [], nil)
        }
    }
    
    /// Wait for every request already handled to be answered and every change handed to the followers.
    func waitUntilIdle() {
        queue.sync {}
    }
    
    /// A reply with the set as it stands.
    ///
    /// - Parameters:
    ///   - status: How the request went.
    ///   - changed: Did the set change?
    ///   - problems: Why the request was refused or invalid, and what was left out of it.
    /// - Returns: The reply.
    func reply(_ status: MuteReply.Status, changed: Bool = false, problems: [String] = []) -> MuteReply {
        let update = pendingUpdate.map { pending in
            var update = pending.update
            update.declined = (declinedRevision ?? 0) >= update.revision
            return update
        }
        return MuteReply(status: status, changed: changed, mutes: MuteFile(list).mutes, problems: problems,
                         notice: notice, update: update, applied: appliedUpdate)
    }
}


// MARK: - Loading
extension SavedMuteSet {
    /// Read the saved set once. Call on ``queue``.
    ///
    /// - Missing: start from Mac Monitor's default set and save it (first run). Say so if no one was logged in.
    /// - Unreadable: it was moved aside. Start from the default set, save it, and say so.
    /// - Newer: keep the file, apply the default set, and refuse changes other than Reset.
    /// - Untrusted directory: apply the default set and refuse every change, rather than write through it.
    ///
    /// Each notice says when the default set leaves out the per-user mutes because no one is logged in, such as at
    /// boot, and how to get them back.
    private func loadIfNeeded() {
        guard !isLoaded else { return }
        isLoaded = true
        do {
            switch try store.load() {
            case .saved(let saved, let warnings, let revision, let declined):
                list = saved
                declinedRevision = declined
                let revisionText = revision.map { "default set revision \($0)" } ?? "no default set revision"
                logger.log("Loaded the saved mute set (\(saved.count) mutes, \(revisionText, privacy: .public)).")
                if !warnings.isEmpty {
                    notice = "Some saved mutes were left out. \(warnings.joined(separator: " "))"
                    logger.error("Left out of the saved mute set: \(warnings.joined(separator: " "), privacy: .public)")
                }
                upgrade(from: revision)
            case .missing:
                notice = startFromDefault()
                logger.log("Created the saved mute set from Mac Monitor's default set (\(self.list.count) mutes).")
            case .unreadable(let reason, let kept):
                let leftOut = startFromDefault().map { " \($0)" } ?? ""
                let moved = kept.map { "It was moved to \($0.path), and" } ?? "It couldn't be moved aside, and"
                notice = """
                    Your saved mute set couldn't be read. \(reason) \(moved) Mac Monitor's default set was \
                    restored.\(leftOut)
                    """
                logger.fault("The saved mute set couldn't be read: \(reason, privacy: .public)")
            case .newer(let version):
                let leftOut: String?
                (list, leftOut) = defaultSet()
                state = .readOnly(version: version)
                notice = """
                    Your saved mute set was written by a newer Mac Monitor (mute file version \(version)). It's kept \
                    as it is, and Mac Monitor's default set applies until you reset it.\(leftOut.map { " \($0)" } ?? "")
                    """
                logger.error("The saved mute set is mute file version \(version). Applying the default set.")
            }
        } catch {
            let leftOut: String?
            (list, leftOut) = defaultSet()
            state = .unavailable(reason: "The saved mute set can't be kept: \(error)")
            /// Reset is refused too, so the per-user mutes come back only with a restart while someone is logged in.
            let untilRestart = leftOut == nil ? "" : " \(Self.noConsoleUserUntilRestart)"
            notice = """
                Mac Monitor can't keep a saved mute set. \(error) Its default set applies, and changes can't be \
                saved.\(untilRestart)
                """
            logger.fault("The saved mute set can't be kept: \(String(describing: error), privacy: .public)")
        }
    }
    
    /// Start from Mac Monitor's default set and save it. A failed save is logged. The next change tries again.
    ///
    /// - Returns: What the default set leaves out because no one is logged in, as a sentence, if anything.
    private func startFromDefault() -> String? {
        let leftOut: String?
        (list, leftOut) = defaultSet()
        do {
            try store.save(list)
        } catch {
            logger.fault("Couldn't save the default mute set: \(String(describing: error), privacy: .public)")
        }
        return leftOut
    }
    
    /// Mac Monitor's default set for whoever is logged in at the console now. Their home folder's caches are muted,
    /// not root's: the Security Extension's own home is `/var/root`.
    ///
    /// With no one logged in (the login window, or only SSH sessions) there's no home folder to mute, so the
    /// per-user mutes are left out rather than guessed. They're added by the next Reset made while someone is.
    ///
    /// - Returns: The set, and a sentence for the user when it leaves out the per-user mutes.
    private func defaultSet() -> (list: MuteList, leftOut: String?) {
        let user = consoleUser()
        let list = MuteList.shippedDefault(for: user)
        guard let user else {
            logger.log("No one is logged in at the console, so the default mute set leaves out the per-user mutes.")
            return (list, Self.noConsoleUser)
        }
        logger.log("""
            The default mute set mutes the caches of \(user.name, privacy: .public) \
            (uid \(user.uid), \(user.home, privacy: .public)).
            """)
        return (list, nil)
    }
    
    /// What the default set leaves out when no one is logged in.
    private static let perUserMutesLeftOut = """
        No one was logged in when Mac Monitor's default mute set was made, so it leaves out the mutes for a home \
        folder's caches and Biome streams.
        """
    
    /// What the default set leaves out when no one is logged in, and how to get it back: Reset.
    static let noConsoleUser = perUserMutesLeftOut + " Reset the saved mute set while you're logged in to add them."
    
    /// What the default set leaves out when no one is logged in and the saved set can't be changed, Reset included.
    static let noConsoleUserUntilRestart = perUserMutesLeftOut
        + " They're added when the Security Extension next starts while someone is logged in."
    
    /// Log a change once at the default level and each entry at info level: mutes persist, so this is their audit
    /// trail.
    ///
    /// - Parameters:
    ///   - operation: What was asked.
    ///   - caller: Who asked.
    ///   - difference: How the set changed.
    ///   - old: The set before.
    ///   - new: The set after.
    func logChange(_ operation: MuteRequest.Operation, by caller: String, _ difference: MuteListDifference,
                           from old: MuteList, to new: MuteList) {
        let (added, removed, changed) = (difference.added, difference.removed, difference.changed)
        logger.log("""
            \(caller, privacy: .public) changed the saved mute set (\(operation.rawValue, privacy: .public)): \
            \(added.count) added, \(removed.count) removed, \(changed.count) changed. \(new.count) mutes now.
            """)
        for (keys, verb, side) in [(added, "added", new), (changed, "changed", new), (removed, "removed", old)] {
            for key in keys {
                guard let mute = side.mute(for: key) else { continue }
                let entry = MuteFile.Entry(mute)
                let events = entry.events.isEmpty ? "every event" : entry.events.joined(separator: ", ")
                logger.info("""
                    \(caller, privacy: .public) \(verb, privacy: .public) \(entry.type, privacy: .public) \
                    \(entry.path, privacy: .public) (\(events, privacy: .public)).
                    """)
            }
        }
    }
}
