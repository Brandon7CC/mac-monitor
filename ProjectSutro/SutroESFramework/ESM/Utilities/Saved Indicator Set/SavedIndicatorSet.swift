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
/// **Packs:** the shipped indicators are a baseline (``IndicatorBaseline``): the ones this build links in, or a signed
/// pack installed since (`SavedIndicatorSet+Packs.swift`). Installing one changes what the set is saved against, so
/// each indicator nobody edited takes the pack's, and every follower gets the set that makes. The Security Extension
/// looks on GitHub for a newer pack once a day, and says so or installs it as the mode decides
/// (`SavedIndicatorSet+Updates.swift`).
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
    /// The installed pack's file, as it was signed.
    let packStore: RootFileStore
    /// The marker kept while the installed pack is read and compiled.
    let packLoadingMarker: RootFileStore
    /// Checks a pack's signature: a release's requirement, unless a test passes its own.
    let verifier: IndicatorPackVerifier
    /// Gets the newest pack from GitHub, or `nil` for a set that never looks for one.
    let fetcher: IndicatorPackFetching?
    /// The file that keeps the update mode and what the last look found.
    let updateStore: RootFileStore
    /// The marker kept while packs are verified and checked, which names them.
    let checkingMarker: RootFileStore
    /// The SHA-256 of each pack being verified or checked now.
    var checking: [String] = []
    /// What time it is.
    let clock: () -> Date
    /// The update mode, when GitHub was last asked, and what that found.
    var updates = IndicatorPackUpdates()
    /// GitHub's last answer and when it came, which stands in for another for
    /// ``IndicatorPackUpdates/answerLifetime``.
    var lastFetch: (at: Date, outcome: Result<FoundPack?, IndicatorPackFetchError>)?
    /// Who waits for the fetch under way: one fetch answers them all.
    var fetchWaiters: [(Result<FoundPack?, IndicatorPackFetchError>) -> Void] = []
    /// Wakes the set to look for a newer pack when one is due.
    var updateTimer: DispatchSourceTimer?
    /// Verifies packs one at a time, off ``queue``.
    let verifying = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.indicators.verifying",
                                  qos: .utility)
    /// How many packs are being verified or wait to be.
    var verifications = 0
    /// The most packs that may be verified or wait to be at once. A request that brings one more is told to try
    /// again, so callers can't pile up packs for the Security Extension to hold and check.
    static let maxVerifications = 4
    /// The indicators this build links in: the floor a pack must be a later release than.
    let linked: IndicatorBaseline
    /// The shipped indicators the set is saved against: ``linked``, or a pack installed since.
    var baseline: IndicatorBaseline {
        didSet { shipped = Indicator.byID(baseline.indicators) }
    }
    /// The shipped indicators, which the set starts from and Restore Defaults brings back.
    var defaults: [Indicator] { baseline.indicators }
    /// Them by identity, which each hit says it is, and whether this Mac edited it.
    private(set) var shipped: [UUID: Indicator]
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
    ///   - linked: The indicators this build links in, unless a test passes its own.
    ///   - verifier: Checks a pack's signature: a release's requirement, unless a test passes its own.
    ///   - fetcher: Gets the newest pack from GitHub. Without one, the set never looks for a pack.
    ///   - clock: What time it is. Tests pass one.
    public init(directory: URL = RootFileStore.systemDirectory, owner: uid_t = 0,
                linked: IndicatorBaseline = .linked, verifier: IndicatorPackVerifier = IndicatorPackVerifier(),
                fetcher: IndicatorPackFetching? = nil, clock: @escaping () -> Date = Date.init) {
        store = RootFileStore(directory: directory, owner: owner, layout: IndicatorFile.layout)
        loadingMarker = RootFileStore(directory: directory, owner: owner, layout: IndicatorFile.loadingLayout)
        packStore = RootFileStore(directory: directory, owner: owner, layout: IndicatorPackFile.installedLayout)
        packLoadingMarker = RootFileStore(directory: directory, owner: owner, layout: IndicatorPackFile.loadingLayout)
        self.verifier = verifier
        self.fetcher = fetcher
        self.clock = clock
        updateStore = RootFileStore(directory: directory, owner: owner, layout: IndicatorPackUpdates.layout)
        checkingMarker = RootFileStore(directory: directory, owner: owner,
                                       layout: IndicatorPackUpdates.checkingLayout)
        self.linked = linked
        baseline = linked
        shipped = Indicator.byID(linked.indicators)
        saved = SavedIndicators(linked.indicators, defaults: linked.indicators)
        compiled = CompiledIndicators([], defaults: shipped, pack: baseline.sequence)
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
    /// A pack's signature is verified off ``queue``, since checking whether its certificate was revoked may wait on
    /// the network, and the set is answered for and followed meanwhile.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``IndicatorRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log, such as "Mac Monitor (pid 123)".
    ///   - reply: Receives a JSON encoded ``IndicatorReply``, on ``queue``. It says what the caller may do, so Mac
    ///     Monitor can disable what it may not.
    public func handle(_ request: Data, access: MuteAccess, caller: String, reply: @escaping (Data) -> Void) {
        queue.async { [self] in
            switch response(to: request, access: access, caller: caller) {
            case .reply(let answer):
                reply(answer)
            case .verify(let pack):
                verify(pack, access: access, caller: caller, reply: reply)
            case .look(let installs, let expecting):
                look(installs: installs, expecting: expecting, access: access, caller: caller, reply: reply)
            }
        }
    }

    /// Wait for every request already handled to be answered and every change handed to the followers.
    func waitUntilIdle() {
        queue.sync {}
    }

    /// What a request gets.
    enum Response {
        /// The encoded reply.
        case reply(Data)
        /// A pack to verify before the request is answered (``answer(to:_:access:caller:looked:)``).
        case verify(PackRequest)
        /// The request brought no pack: look on GitHub for the newest, to check it or install it, and when it's to
        /// be installed, the sequence the caller expects it to have, if it said.
        case look(installs: Bool, expecting: Int?)
    }

    /// Read a request and answer it, or hand back the pack it brings, or asks for, to be verified first. Call on
    /// ``queue``.
    ///
    /// - Parameters:
    ///   - data: A JSON encoded ``IndicatorRequest``.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The encoded reply, for a list the one cached since the last change, or the pack to verify or look
    ///   for.
    func response(to data: Data, access: MuteAccess, caller: String) -> Response {
        loadIfNeeded()
        var answer: IndicatorReply
        do {
            let request = try IndicatorRequest.decode(data)
            if request.operation == .list {
                if let cached = listReplies[access] { return .reply(cached) }
                answer = reply(.ok)
                answer.access = access
                let encoded = answer.encoded()
                listReplies[access] = encoded
                return .reply(encoded)
            }
            if request.operation.bringsPack {
                switch packRequest(request, access: access, caller: caller) {
                case .success(let pack?): return .verify(pack)
                case .success(nil):
                    return .look(installs: request.operation == .installPack, expecting: request.expecting)
                case .failure(let refusal): answer = refusal.reply
                }
            } else if request.operation == .setPackMode {
                answer = setMode(request, access: access, caller: caller)
            } else {
                answer = perform(request, access: access, caller: caller)
            }
        } catch {
            answer = reply(error.status(), failure: error.description)
        }
        answer.access = access
        return .reply(answer.encoded())
    }

    /// Why a caller that may only read the set is refused a change. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - operation: What was asked.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply that refuses it, or `nil` when the caller may change the set.
    func accessRefusal(of operation: IndicatorRequest.Operation, access: MuteAccess,
                       caller: String) -> IndicatorReply? {
        guard let refusal = access.refusal(changing: "the indicators") else { return nil }
        logger.error("""
            Refused \(operation.rawValue, privacy: .public) from \(caller, privacy: .public), which may \
            only read the indicators (\(access.rawValue, privacy: .public)).
            """)
        return reply(refusal.status, failure: refusal.problem)
    }

    /// Why a change is refused whatever it is: the caller may only read the set, or the set can't be changed. Call
    /// on ``queue``.
    ///
    /// - Parameters:
    ///   - operation: What was asked.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply that refuses it, or `nil` when the change may be made.
    func refusal(of operation: IndicatorRequest.Operation, access: MuteAccess, caller: String) -> IndicatorReply? {
        if let refusal = accessRefusal(of: operation, access: access, caller: caller) { return refusal }
        switch state {
        case .readOnly:
            return reply(.readOnly, failure: """
                The indicators were saved by a newer Mac Monitor, so they can't be changed here. Update Mac Monitor \
                to change them.
                """)
        case .unavailable(let reason):
            return reply(.storageFailed, failure: reason)
        case .writable:
            return nil
        }
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
        if let refusal = refusal(of: request.operation, access: access, caller: caller) { return refusal }
        let next: [Indicator], nextCompiled: CompiledIndicators
        do {
            next = try nextIndicators(for: request)
            try IndicatorFile.validate(next)
            /// Restore Defaults also forgets what someone chose, which the indicators alone don't show.
            let forgets = request.operation == .reset && saved.hasChoices
            guard forgets || !next.isIdentical(to: saved.indicators) else { return reply(.ok) }
            nextCompiled = CompiledIndicators(next, defaults: shipped, pack: baseline.sequence, reusing: compiled)
            try IndicatorFile.validate(nextCompiled)
            try checkRuns(next, compiled: nextCompiled)
        } catch {
            return reply(.invalid, failure: "\(error)")
        }
        var nextSaved = saved
        nextSaved.indicators = next
        if request.operation == .reset { nextSaved.forgetChoices() }
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

    /// Refuse a set that brings an indicator the Security Extension can't run. Every indicator runs there, so one
    /// it can't run would match nothing.
    ///
    /// Two are let through, and stay listed as problems. One the set already has with the same rule, as a set saved
    /// by Mac Monitor 3.1 may hold: it's refused only once its rule changes. And one the baseline ships as it
    /// ships it, which a pack may hold for a newer Mac Monitor.
    ///
    /// - Parameters:
    ///   - next: The set a request asks for.
    ///   - compiled: It, compiled.
    /// - Throws: ``IndicatorFileError/cannotRun(_:_:)`` for the first such indicator, in the set's order.
    func checkRuns(_ next: [Indicator], compiled: CompiledIndicators) throws(IndicatorFileError) {
        guard !compiled.problems.isEmpty else { return }
        let reasons = Dictionary(compiled.problems.map { ($0.id, $0.reason) }) { first, _ in first }
        let had = Indicator.byID(saved.indicators)
        for indicator in next {
            guard let reason = reasons[indicator.id], had[indicator.id]?.rule != indicator.rule,
                  shipped[indicator.id]?.rule != indicator.rule else { continue }
            throw .cannotRun(indicator.name, reason)
        }
    }

    /// Make a set the current one, and hand it to every follower. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - next: The set as saved.
    ///   - nextCompiled: The set, compiled.
    func replace(with next: SavedIndicators, compiled nextCompiled: CompiledIndicators) {
        saved = next
        compiled = nextCompiled
        notice = nil
        listReplies = [:]
        followers.notify { $0(nextCompiled) }
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
                       failure: failure, notice: notice, readOnly: state != .writable,
                       pack: describe(baseline), baseline: defaults)
    }
}
