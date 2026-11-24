//
//  SavedIndicatorSet+Packs.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation
import OSLog


// MARK: - Installing a pack
/// A signed indicator pack takes the place of the shipped indicators the set is saved against (``IndicatorBaseline``),
/// without a Mac Monitor release.
///
/// A pack is installed only when, in this order, and the first that fails leaves everything as it was:
/// 1. The caller may change the set, and the set can be changed
/// 2. Its signature is accepted: Swiftly Detecting's Developer ID, with a certificate valid now and not revoked
///    (``IndicatorPackVerifier``)
/// 3. Its payload is a pack this build reads, with every core identity and no retired one
///    (``IndicatorPack/decode(_:)``)
/// 4. It's a later release than the installed pack and the one this build links in
/// 5. Every indicator of its that this build should run compiles
/// 6. The Mac's set, saved against it, is within ``IndicatorLimits``, compiled too
/// 7. Its file is kept, exactly as it was signed, beside the saved set (``IndicatorPackFile/installedLayout``)
///
/// The set saved against the pack keeps what someone changed: an indicator nobody edited takes the pack's, with the
/// switches, tactic, technique and severity someone chose. A deleted one stays deleted, and an edited one stays as it
/// was saved. One the pack no longer has goes, unless it was edited. One that's new arrives as the pack has it.
///
/// A check (``IndicatorRequest/Operation/checkPack``) does 2 to 6 and replies with the set as installing would
/// leave it, and changes nothing. A request that brings no pack has the Security Extension get the newest from
/// GitHub first (`SavedIndicatorSet+Updates.swift`).
extension SavedIndicatorSet {
    /// A pack to check or install: one a request brought, or one a look found on GitHub.
    struct PackRequest {
        /// The pack's file.
        let file: Data
        /// Install it, or only say what installing it would change?
        let installs: Bool
        /// Is it the daily look's? Then whether it's installed is decided when it's answered, by the mode and the
        /// set as they are then.
        var daily = false
        /// The sequence the caller expects it to have, or `nil` when it didn't say.
        var expecting: Int?
        /// May verifying it ask the network whether its certificate was revoked? Only for a caller that may change
        /// the set (``IndicatorPackVerifier/Mode/checking``).
        var usesNetwork = true
        /// What the release it came from says of it, for a pack a look found. A check's reply passes it on.
        var notes: String?
    }

    /// A request refused before its pack is verified, as its reply.
    struct Refused: Error {
        /// The reply.
        let reply: IndicatorReply
    }

    /// The set a verified pack makes.
    struct PackPlan {
        /// The pack, as the baseline.
        let baseline: IndicatorBaseline
        /// The set saved against it.
        let saved: SavedIndicators
        /// That set, compiled.
        let compiled: CompiledIndicators
        /// That set, as its file.
        let bytes: Data
    }

    /// Read a request to check or install a pack, and refuse what its caller may not ask before any work is done
    /// for it. Call on ``queue``.
    ///
    /// Anyone who may list the set may check a pack. Only a caller that may change it installs one, and while the
    /// mode is off, only such a caller has the Security Extension ask GitHub.
    ///
    /// - Parameters:
    ///   - request: The request: a check or an install.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    /// - Returns: The pack to verify, `nil` to look on GitHub for the newest, or the refusal.
    func packRequest(_ request: IndicatorRequest, access: MuteAccess, caller: String)
        -> Result<PackRequest?, Refused> {
        let installs = request.operation == .installPack
        if installs, let refusal = refusal(of: request.operation, access: access, caller: caller) {
            return .failure(Refused(reply: refusal))
        }
        if let file = request.pack, !file.isEmpty {
            return .success(PackRequest(file: file, installs: installs, expecting: request.expecting,
                                        usesNetwork: access == .write))
        }
        guard fetcher != nil else {
            return .failure(Refused(reply: reply(.invalid, failure: """
                The request brings no pack, and this Security Extension doesn't look for one.
                """)))
        }
        if updates.mode == .off, let refusal = access.refusal(changing: "the indicators") {
            logger.error("Refused a look for a pack from \(caller, privacy: .public): updates are off.")
            return .failure(Refused(reply: reply(refusal.status, failure: """
                Indicator pack updates are off on this Mac, so only someone who may change the indicators can look \
                for one.
                """)))
        }
        return .success(nil)
    }

    /// Answer a request that brought a pack, now that its signature was checked. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - pack: The request's pack.
    ///   - verification: The pack's payload and signer, or why its signature wasn't accepted.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    ///   - looked: Did the pack come from GitHub, for a look? Then what it came to is remembered
    ///     (``noteLook(available:problem:)``).
    /// - Returns: The encoded reply: the set as it stands after an install, or as an install would leave it.
    func answer(to pack: PackRequest, _ verification: Result<VerifiedIndicatorPack, IndicatorPackError>,
                access: MuteAccess, caller: String, looked: Bool = false) -> Data {
        var answer: IndicatorReply
        /// The daily look installs only if the mode is still automatic and the set can be changed now. Otherwise it
        /// says a newer pack is out, as the notify mode does.
        let installs = pack.daily ? updates.mode == .automatic && state == .writable : pack.installs
        do throws(IndicatorPackRefusal) {
            /// The set may have become read-only while the pack was verified.
            if installs, let refusal = refusal(of: .installPack, access: access, caller: caller) {
                answer = refusal
            } else {
                let plan = try plan(for: verification)
                if let expecting = pack.expecting, plan.baseline.sequence != expecting {
                    throw .changed(offered: plan.baseline.sequence, expected: expecting)
                }
                if installs {
                    answer = install(plan, file: pack.file, caller: caller)
                } else {
                    if looked { noteLook(available: plan.baseline.sequence, problem: nil) }
                    answer = preview(plan)
                    answer.notes = pack.notes
                }
            }
        } catch .notNewer where looked {
            /// A pack was installed while GitHub was asked about this one, so there's nothing newer.
            noteLook(available: nil, problem: nil)
            answer = reply(.ok)
        } catch .changed(let offered, let expected) {
            if looked { noteLook(available: offered, problem: nil) }
            answer = reply(.invalid, failure: IndicatorPackRefusal.changed(offered: offered,
                                                                           expected: expected).description)
        } catch {
            let problem = Self.brief(error.description)
            logger.error("Refused a pack from \(caller, privacy: .public): \(problem, privacy: .public)")
            if looked { noteLook(available: nil, problem: problem) }
            answer = reply(.invalid, failure: problem)
        }
        answer.access = access
        return answer.encoded()
    }

    /// A reason cut to a few lines at most. A pack's file and its certificates aren't trusted, and what they say
    /// about themselves ends up in a refusal.
    ///
    /// - Parameter text: The reason.
    /// - Returns: Its first 500 characters.
    static func brief(_ text: String) -> String {
        String(text.prefix(500))
    }

    /// The set a pack makes, checked: steps 2 to 6 above. Nothing changes. Call on ``queue``.
    ///
    /// - Parameter verification: The pack's payload and signer, or why its signature wasn't accepted.
    /// - Returns: The pack as the baseline, and the set saved against it, compiled and encoded.
    /// - Throws: ``IndicatorPackRefusal`` for the first step that fails.
    func plan(for verification: Result<VerifiedIndicatorPack, IndicatorPackError>) throws(IndicatorPackRefusal)
        -> PackPlan {
        let payload: Data
        switch verification {
        case .success(let verified): payload = verified.payload
        case .failure(let error): throw .signature(error.message)
        }
        let next = try baseline.replacement(from: payload)
        let nextShipped = Indicator.byID(next.indicators)
        /// The pack's indicators on their own, since the set may not have one that was deleted or edited here.
        let alone = CompiledIndicators(next.indicators, defaults: nextShipped, pack: next.sequence, reusing: compiled)
        if let problem = alone.problems.first(where: { nextShipped[$0.id]?.isSupported == true }) {
            throw .cannotRun(name: nextShipped[problem.id]?.name ?? problem.id.uuidString, reason: problem.reason)
        }
        /// The set as it's saved now, read against the pack: what a later build's indicators do to a saved file.
        guard let resolved = SavedIndicators(object: saved.encodedObject(), defaults: next.indicators,
                                             retired: next.retired) else {
            throw .storage("This Mac's indicators can't be saved against it.")
        }
        let nextCompiled: CompiledIndicators
        do throws(IndicatorFileError) {
            try IndicatorFile.validate(resolved.indicators)
            nextCompiled = CompiledIndicators(resolved.indicators, defaults: nextShipped, pack: next.sequence,
                                              reusing: compiled)
            try IndicatorFile.validate(nextCompiled)
        } catch {
            throw .pastLimit(error.description)
        }
        guard let bytes = IndicatorFile(resolved).encoded(), bytes.count <= IndicatorLimits.maxFileBytes else {
            throw .pastLimit("They would be larger than \(store.maxSizeText) saved.")
        }
        return PackPlan(baseline: next, saved: resolved, compiled: nextCompiled, bytes: bytes)
    }

    /// Keep a pack's file, then make its set the current one and hand it to every follower: step 7. Call on
    /// ``queue``.
    ///
    /// The pack's file is what installs it. The saved set's file reads the same against the pack as the set kept
    /// here, so a failure to write it again is only logged.
    ///
    /// - Parameters:
    ///   - plan: The set the pack makes.
    ///   - file: The pack's file, exactly as it was verified.
    ///   - caller: Names the caller in the log.
    /// - Returns: The reply, with the set as it stands.
    private func install(_ plan: PackPlan, file: Data, caller: String) -> IndicatorReply {
        do {
            try packStore.write(file)
        } catch {
            logger.fault("""
                Couldn't keep the pack \(caller, privacy: .public) asked to install: \
                \(String(describing: error), privacy: .public)
                """)
            return reply(.storageFailed, failure: IndicatorPackRefusal.storage("\(error)").description)
        }
        do {
            try store.write(plan.bytes)
        } catch {
            logger.fault("""
                Couldn't save the indicators again after installing a pack: \
                \(String(describing: error), privacy: .public)
                """)
        }
        logger.log("""
            \(caller, privacy: .public) installed indicator pack \(plan.baseline.sequence) \
            (commit \(plan.baseline.commit ?? "", privacy: .public), \(plan.baseline.indicators.count) indicators) \
            over pack \(self.baseline.sequence) (\(self.baseline.source.rawValue, privacy: .public)).
            """)
        logChange(.installPack, by: caller, from: saved.indicators, to: plan.saved.indicators)
        baseline = plan.baseline
        settleUpdates()
        replace(with: plan.saved, compiled: plan.compiled)
        return reply(.ok, changed: true)
    }

    /// The reply to a check: the set, its problems and the shipped indicators as installing the pack would leave
    /// them. Call on ``queue``.
    ///
    /// - Parameter plan: The set the pack makes.
    /// - Returns: The reply, which says nothing changed.
    private func preview(_ plan: PackPlan) -> IndicatorReply {
        var answer = reply(.ok)
        answer.indicators = plan.saved.indicators
        answer.problems = plan.compiled.problems.map { IndicatorReply.Problem(id: $0.id, reason: $0.reason) }
        answer.pack = describe(plan.baseline)
        answer.baseline = plan.baseline.indicators
        return answer
    }
}


// MARK: - Loading the installed pack
extension SavedIndicatorSet {
    /// Which release the shipped indicators are, and whether the build links them in or a pack was installed since,
    /// for `macmonitor status`. Ask from any thread, but never from a follower.
    public var packStatus: IndicatorPackStatus {
        queue.sync {
            loadIfNeeded()
            return describe(baseline)
        }
    }

    /// Read the installed pack, if there is one, and compile the shipped indicators, its or this build's. Call on
    /// ``queue``, before the saved set is read.
    ///
    /// - A loading marker left by a crash: move the pack aside. This build's indicators apply.
    /// - Missing: this build's indicators apply.
    /// - Unreadable, with a signature that isn't accepted, or not a pack this build reads: move it aside. This
    ///   build's indicators apply.
    /// - No later than the release this build links in: remove it. A Mac Monitor update brought a newer one.
    /// - Otherwise it's the baseline. Its signature is checked as when it was installed, but for its certificate's
    ///   dates, and without the network (``IndicatorPackVerifier/Mode/loading``).
    ///
    /// The marker is kept while the pack is read and its indicators are compiled, so a pack that stops the Security
    /// Extension is moved aside at the next start.
    ///
    /// - Returns: The shipped indicators, compiled (``selfTest()``), and what to tell the user about the installed
    ///   pack, if anything.
    func loadBaseline() -> (shippedSet: CompiledIndicators, notice: String?) {
        /// A directory that can't be trusted is the saved set's to report.
        guard let marker = try? packLoadingMarker.read() else { return (selfTest(), nil) }
        guard marker == .missing else {
            packLoadingMarker.remove()
            /// It counts against this very file, so a look that finds it again doesn't try it for long.
            if case .read(let file)? = try? packStore.read() {
                updates.strike([IndicatorPackUpdates.digest(of: file)])
                saveUpdates()
            }
            logger.fault("The last load of the installed indicator pack never finished. Moving it aside.")
            return (selfTest(), setAsidePack("The Security Extension stopped while it loaded it."))
        }
        let file: Data
        switch (try? packStore.read()) ?? .missing {
        case .missing: return (selfTest(), nil)
        case .unreadable(let reason): return (selfTest(), setAsidePack(reason))
        case .tooLarge(let bytes):
            return (selfTest(), setAsidePack("It's \(bytes) bytes, larger than \(packStore.maxSizeText)."))
        case .read(let data): file = data
        }
        let marked = (try? packLoadingMarker.write(Data())) != nil
        defer { if marked { packLoadingMarker.remove() } }
        do {
            let pack = try IndicatorPack.decode(try verifier.verify(file, .loading).payload)
            guard pack.pack.sequence > linked.sequence else {
                packStore.remove()
                logger.log("""
                    Removed installed indicator pack \(pack.pack.sequence): this Mac Monitor links in pack \
                    \(self.linked.sequence).
                    """)
                return (selfTest(), nil)
            }
            baseline = IndicatorBaseline(installed: pack)
            logger.log("""
                Loaded installed indicator pack \(pack.pack.sequence) (commit \(pack.pack.commit, privacy: .public), \
                \(pack.indicators.count) indicators).
                """)
            return (selfTest(), nil)
        } catch {
            let reason = (error as? IndicatorPackError)?.message ?? "\(error)"
            return (selfTest(), setAsidePack(reason))
        }
    }

    /// Move an installed pack that can't be used aside, so this build's indicators apply.
    ///
    /// - Parameter reason: Why it can't be used, as a sentence.
    /// - Returns: What to tell the user.
    private func setAsidePack(_ reason: String) -> String {
        let kept = packStore.moveAside()
        logger.fault("The installed indicator pack can't be used: \(reason, privacy: .public)")
        let moved = kept.map { "It was moved to \($0.path)." } ?? "It couldn't be moved aside."
        return """
            The installed indicator pack couldn't be used. \(reason) \(moved) The indicators this Mac Monitor came \
            with apply.
            """
    }
}
