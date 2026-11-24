//
//  SavedIndicatorSet+Verifying.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation
import OSLog


// MARK: - Verifying a pack
/// A pack's signature is verified off the set's queue, since checking whether its certificate was revoked may wait
/// on the network, and the set is answered for and followed meanwhile. Packs are verified one at a time, only a few
/// may wait, and one the Security Extension stopped over twice isn't read again.
extension SavedIndicatorSet {
    /// Verify a pack off ``queue``, one at a time, then answer the request that brought it, or asked for it, on
    /// ``queue``. Call on ``queue``.
    ///
    /// With ``maxVerifications`` packs already being verified or waiting, the request is told to try again
    /// (``MuteReply/Status/unreachable``). The daily look's pack always waits its turn: it comes at most once an
    /// hour, and nobody else's requests can crowd it out.
    ///
    /// A marker names the pack until it's answered for. A pack the Security Extension stopped over twice is refused
    /// without being read again (``IndicatorPackUpdates/isPassedOver(_:)``), so one that stops it can't do so every
    /// day, or whenever someone asks.
    ///
    /// - Parameters:
    ///   - pack: The pack, and whether to install it.
    ///   - access: What the caller may do.
    ///   - caller: Names the caller in the log.
    ///   - looked: Did the pack come from GitHub, for a look, rather than with the request?
    ///   - reply: Receives the encoded reply, on ``queue``.
    func verify(_ pack: PackRequest, access: MuteAccess, caller: String, looked: Bool = false,
                reply: @escaping (Data) -> Void) {
        guard pack.daily || verifications < Self.maxVerifications else {
            logger.error("Told \(caller, privacy: .public) to try again: too many packs wait to be verified.")
            var busy = self.reply(.unreachable, failure: """
                The Security Extension is checking other indicator packs. Try again in a moment.
                """)
            busy.access = access
            return reply(busy.encoded())
        }
        let digest = IndicatorPackUpdates.digest(of: pack.file)
        guard !updates.isPassedOver(digest) else {
            let problem = IndicatorPackRefusal.stoppedTheExtension.description
            logger.error("Passed over a pack from \(caller, privacy: .public): \(problem, privacy: .public)")
            if looked { noteLook(available: nil, problem: problem) }
            var refused = self.reply(.invalid, failure: problem)
            refused.access = access
            return reply(refused.encoded())
        }
        verifications += 1
        mark(checking: digest, true)
        verifying.async { [self] in
            let verification = verification(of: pack)
            queue.async { [self] in
                verifications -= 1
                let answer = answer(to: pack, verification, access: access, caller: caller, looked: looked)
                mark(checking: digest, false)
                reply(answer)
            }
        }
    }

    /// Verify a pack's signature, as one about to be installed. It may wait on the network, so it's called off
    /// ``queue`` (``verify(_:access:caller:looked:reply:)``).
    ///
    /// - Parameter pack: The pack, and whether verifying it may ask the network.
    /// - Returns: The pack's payload and signer, or why its signature wasn't accepted.
    func verification(of pack: PackRequest) -> Result<VerifiedIndicatorPack, IndicatorPackError> {
        do throws(IndicatorPackError) {
            return .success(try verifier.verify(pack.file, pack.usesNetwork ? .installing : .checking))
        } catch {
            return .failure(error)
        }
    }

    /// Note that a pack is being verified or checked, or no longer is, and keep the marker that names those that
    /// are. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - digest: The pack file's SHA-256.
    ///   - isChecking: Is it being checked now?
    func mark(checking digest: String, _ isChecking: Bool) {
        if isChecking {
            checking.append(digest)
        } else if let index = checking.firstIndex(of: digest) {
            checking.remove(at: index)
        }
        guard !checking.isEmpty else {
            checkingMarker.remove()
            return
        }
        _ = try? checkingMarker.write((try? JSONEncoder().encode(checking)) ?? Data())
    }
}
