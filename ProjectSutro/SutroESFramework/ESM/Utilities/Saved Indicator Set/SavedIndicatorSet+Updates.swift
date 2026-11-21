//
//  SavedIndicatorSet+Updates.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation
import OSLog


// MARK: - Looking for a newer pack
/// The Security Extension looks on GitHub for a newer indicator pack itself, as it does for Mac Monitor's releases:
/// nothing about the pack comes from Mac Monitor or `macmonitor`, which only ask it to look.
///
/// A look reads the indicators repository's releases, takes the newest pack release (``IndicatorPackRelease``), and
/// downloads its pack only when its tag is later than the indicators this Mac has. The pack is then verified and
/// checked as one brought in a file is (`SavedIndicatorSet+Packs.swift`), and installed when that was asked.
///
/// - **When:** once a day on its own, unless the mode is off (``IndicatorPackMode``), and whenever someone asks. In
///   the automatic mode the daily look installs what it finds. Otherwise it only remembers that a newer pack is out,
///   which every reply then says (``IndicatorPackStatus/available``).
/// - **How often:** GitHub is asked at most once every five minutes, whoever asks. Until then its last answer stands,
///   and requests that arrive while it's being asked share the one answer.
/// - **Who:** anyone who may list the set may ask for a look. While the mode is off, only a caller that may change
///   the set has GitHub asked. A look someone asks for never puts the daily look off, and one GitHub doesn't answer
///   forgets nothing an earlier look found.
/// - **What's kept:** the mode, when GitHub was last asked, when the daily look last ran, and the newer pack found
///   (``IndicatorPackUpdates``).
///
/// - Important: Not in 3.2. This is done and tested, and waits for a later release. Until then it's off where it
///   starts, and each place says so in a comment that starts "Not in 3.2":
///   - `SecurityExtension/main.swift` makes the set without a fetcher, so it never looks.
///   - Settings > General leaves out ``IndicatorPackSettings``, and Mac Monitor doesn't offer a pack as it opens.
///   - `macmonitor help indicators` leaves out `pack check`, `pack mode` and `pack install` without a file.
///   A signed pack's file still installs (`pack install FILE`), and `pack status` and `pack verify` work.
extension SavedIndicatorSet {
    /// A newer pack GitHub has.
    struct FoundPack {
        /// The pack's file.
        let file: Data
        /// What its release says of it (``IndicatorPackRelease/notes``).
        let notes: String?
    }

    /// Read the update state, if it was kept, and count the packs the Security Extension stopped over, if a marker
    /// names any. Call on ``queue``, before the installed pack is loaded.
    func loadUpdates() {
        if case .read(let data)? = try? updateStore.read(), let kept = IndicatorPackUpdates(data) { updates = kept }
        guard case .read(let marker)? = try? checkingMarker.read() else { return }
        checkingMarker.remove()
        guard let digests = try? JSONDecoder().decode([String].self, from: marker), !digests.isEmpty else { return }
        logger.fault("The Security Extension stopped while it was checking \(digests.count) indicator pack(s).")
        updates.strike(digests)
        saveUpdates()
    }

    /// Keep the update state, and stop answering lists from before it changed. Call on ``queue``.
    ///
    /// - Returns: Whether it was kept. A failure is logged.
    @discardableResult
    func saveUpdates() -> Bool {
        listReplies = [:]
        do {
            try updateStore.write(updates.encoded())
            return true
        } catch {
            logger.error("""
                Couldn't keep the indicator pack update state: \(String(describing: error), privacy: .public)
                """)
            return false
        }
    }

    /// Start looking for a newer pack once a day. Does nothing for a set without a fetcher, or one already started.
    ///
    /// - Parameters:
    ///   - first: How long until the set first asks whether a look is due: five minutes, so the Mac has its network
    ///     once it has started.
    ///   - every: How often it asks after that: hourly. A look happens only when one is due
    ///     (``IndicatorPackUpdates/isDue(at:)``).
    public func startUpdates(first: TimeInterval = 5 * 60, every: TimeInterval = 60 * 60) {
        queue.async { [self] in
            loadIfNeeded()
            guard fetcher != nil, updateTimer == nil else { return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + first, repeating: every, leeway: .seconds(30))
            timer.setEventHandler { [weak self] in self?.lookIfDue() }
            timer.resume()
            updateTimer = timer
        }
    }

    /// Look for a newer pack if the mode has the Security Extension look on its own and a day has passed since its
    /// last look that GitHub answered, and install what's found in the automatic mode. Call on ``queue``.
    ///
    /// A look GitHub doesn't answer is tried again the next time this is called: hourly, once started.
    ///
    /// - Parameter completion: Called on ``queue`` once the look is over, or at once when none is due.
    func lookIfDue(then completion: @escaping () -> Void = {}) {
        guard fetcher != nil, updates.isDue(at: clock()) else { return completion() }
        look(installs: updates.mode == .automatic, daily: true, access: .write, caller: "The daily look") { _ in
            completion()
        }
    }

    /// Look on GitHub for the newest pack, then check it or install it. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - installs: Install a newer pack, or only say what installing it would change?
    ///   - daily: Is it the daily look? Then GitHub answering counts as the day's look, and whether to install is
    ///     decided again once the pack is verified.
    ///   - expecting: The sequence the caller expects the pack to have, or `nil` when it didn't say.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    ///   - reply: Receives the encoded reply, on ``queue``: the set as it stands when there's no newer pack, as an
    ///     install leaves or would leave it when there is, or ``MuteReply/Status/unreachable`` when GitHub couldn't
    ///     be asked.
    func look(installs: Bool, daily: Bool = false, expecting: Int? = nil, access: MuteAccess, caller: String,
              reply: @escaping (Data) -> Void) {
        newestPack { [self] outcome in
            if daily, case .success = outcome {
                updates.looked = clock()
                saveUpdates()
            }
            switch outcome {
            case .failure(let error):
                logger.error("""
                    A look for an indicator pack for \(caller, privacy: .public) failed: \
                    \(error.description, privacy: .public)
                    """)
                /// What an earlier look found is still out: only why this one found nothing is new.
                updates.problem = Self.brief(error.description)
                saveUpdates()
                var answer = self.reply(.unreachable, failure: error.description)
                answer.access = access
                reply(answer.encoded())
            case .success(nil):
                noteLook(available: nil, problem: nil)
                var answer = self.reply(.ok)
                answer.access = access
                reply(answer.encoded())
            case .success(let found?):
                verify(PackRequest(file: found.file, installs: installs, daily: daily, expecting: expecting,
                                   notes: found.notes),
                       access: access, caller: caller, looked: true, reply: reply)
            }
        }
    }

    /// The newest pack on GitHub that's later than the indicators this Mac has. Call on ``queue``.
    ///
    /// GitHub's last answer stands for ``IndicatorPackUpdates/answerLifetime``, and one fetch answers everyone who
    /// asks while it's under way.
    ///
    /// - Parameter completion: Called once, on ``queue``, with the pack, `nil` when GitHub has none later, or why it
    ///   couldn't be fetched.
    func newestPack(completion: @escaping (Result<FoundPack?, IndicatorPackFetchError>) -> Void) {
        guard let fetcher else {
            return completion(.failure(.unreachable("This Security Extension doesn't look for indicator packs.")))
        }
        let now = clock()
        if let last = lastFetch, last.at <= now,
           now.timeIntervalSince(last.at) < IndicatorPackUpdates.answerLifetime {
            return completion(last.outcome)
        }
        fetchWaiters.append(completion)
        guard fetchWaiters.count == 1 else { return }
        let installed = baseline.sequence
        fetcher.fetch(IndicatorPackRelease.releasesURL, limit: IndicatorLimits.maxFileBytes) { [self] listing in
            let release: IndicatorPackRelease?
            do throws(IndicatorPackFetchError) {
                let answer = try listing.get()
                release = try IndicatorPackRelease.newest(in: answer.data, status: answer.status)
            } catch {
                return fetched(.failure(error), since: installed)
            }
            guard let release, release.sequence > installed else { return fetched(.success(nil), since: installed) }
            fetcher.fetch(release.download, limit: IndicatorLimits.maxFileBytes) { [self] download in
                fetched(download.flatMap { answer in
                    answer.status == 200 ? .success(FoundPack(file: answer.data, notes: release.notes))
                        : .failure(.download(status: answer.status))
                }, since: installed)
            }
        }
    }

    /// Remember GitHub's answer and when it came, and hand it to everyone waiting for it. Call from any queue.
    ///
    /// When GitHub was asked is kept at once, whatever the answer comes to, so a restart doesn't ask again before a
    /// day has passed.
    ///
    /// An answer about a baseline that a pack has replaced since isn't remembered: it was chosen for the indicators
    /// this Mac had when GitHub was asked.
    ///
    /// - Parameters:
    ///   - outcome: The pack, `nil` for none later, or why it couldn't be fetched.
    ///   - installed: The baseline's sequence when GitHub was asked.
    private func fetched(_ outcome: Result<FoundPack?, IndicatorPackFetchError>, since installed: Int) {
        queue.async { [self] in
            let now = clock()
            updates.checked = now
            saveUpdates()
            lastFetch = baseline.sequence == installed ? (now, outcome) : nil
            let waiters = fetchWaiters
            fetchWaiters = []
            for waiter in waiters { waiter(outcome) }
        }
    }

    /// Remember what a look came to, and keep it. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - available: The sequence of a newer pack that was verified and could be installed, or `nil`.
    ///   - problem: Why the look found nothing it could use, or `nil` when it went well.
    func noteLook(available: Int?, problem: String?) {
        updates.available = available
        updates.problem = problem.map(Self.brief)
        saveUpdates()
    }

    /// Bring the update state in line with a pack that was just installed: GitHub's last answer is installed now, or
    /// older than what is, and a pack that was out is only still news when it's later. Nothing is written when that
    /// changes nothing. Call on ``queue``.
    func settleUpdates() {
        lastFetch = nil
        let before = updates
        if let available = updates.available, available <= baseline.sequence { updates.available = nil }
        updates.problem = nil
        if updates != before { saveUpdates() }
    }

    /// Change the mode. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - request: The request, which names the mode.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply, with the set as it stands and the mode it has now.
    func setMode(_ request: IndicatorRequest, access: MuteAccess, caller: String) -> IndicatorReply {
        /// Whatever state the set is in: someone has to be able to turn the daily look off while the set itself
        /// can't be changed.
        if let refusal = accessRefusal(of: request.operation, access: access, caller: caller) { return refusal }
        guard let mode = request.mode else {
            return reply(.invalid, failure: "Say which mode: off, notify or auto.")
        }
        let previous = updates.mode
        guard mode != previous else { return reply(.ok) }
        updates.mode = mode
        guard saveUpdates() else {
            updates.mode = previous
            return reply(.storageFailed, failure: """
                The mode couldn't be saved, so indicator pack updates are still \(previous.rawValue).
                """)
        }
        logger.log("""
            \(caller, privacy: .public) changed indicator pack updates from \
            \(previous.rawValue, privacy: .public) to \(mode.rawValue, privacy: .public).
            """)
        return reply(.ok)
    }

    /// What a reply says about a baseline, and about looking for a newer one. Call on ``queue``.
    ///
    /// - Parameter baseline: The shipped indicators now, or as a pack being checked would make them.
    /// - Returns: The status.
    func describe(_ baseline: IndicatorBaseline) -> IndicatorPackStatus {
        var status = baseline.status(linked: linked.sequence)
        status.mode = updates.mode
        status.checked = updates.checked.map { ISO8601DateFormatter().string(from: $0) }
        status.available = updates.available
        status.problem = updates.problem
        return status
    }
}
