//
//  SavedMuteSet+Upgrades.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Upgrades
/// Bringing the saved set up to a newer default set (``MuteSetUpgrade``): by itself for a set no one changed, and
/// when asked for one someone did. Everything here runs on ``SavedMuteSet/queue``.
extension SavedMuteSet {
    /// Bring a saved set from an earlier default set revision up to date, while loading. One no one changed becomes
    /// the current default set and is saved, unless the user declined it. One someone changed is kept, and its merge
    /// offered (``refreshUpdate()``). A set saved without a revision gets the closest one. Call on ``queue``.
    ///
    /// - Parameter revision: The revision it was saved with, if any.
    func upgrade(from revision: Int?) {
        let plan = MuteSetUpgrade.plan(for: list, revision: revision)
        defaultsRevision = plan?.revision ?? revision ?? MuteSet.currentRevision
        guard let plan, plan.wasDefault, plan.merged != list,
              (declinedRevision ?? 0) < MuteSet.currentRevision else { return refreshUpdate() }
        let update = MuteSetUpdate(from: list, to: plan.merged, after: plan.revision)
        do {
            try store.save(plan.merged)
        } catch {
            logger.fault("Couldn't save the updated default mute set: \(String(describing: error), privacy: .public)")
            notice = [notice, """
                Mac Monitor couldn't update your saved mute set to the \(update.release) default set, so it's kept as \
                it was. \(error) It tries again when the Security Extension next starts.
                """].compactMap { $0 }.joined(separator: " ")
            return
        }
        logChange(.update, by: "Mac Monitor \(update.release)", list.difference(to: plan.merged), from: list,
                  to: plan.merged)
        list = plan.merged
        defaultsRevision = MuteSet.currentRevision
        declinedRevision = nil
        appliedUpdate = update
    }
    
    /// Decline the newer default set offered: it's saved with the set, so Mac Monitor stops asking at launch and the
    /// set is never updated by itself to it. Settings > Path Muting and `macmonitor mute update` still offer it.
    /// Call on ``queue``.
    ///
    /// - Parameter caller: Who declined, for the log.
    /// - Returns: The reply. Nothing to decline is answered as is.
    func decline(by caller: String) -> MuteReply {
        guard let offered = pendingUpdate?.update.revision, (declinedRevision ?? 0) < offered else { return reply(.ok) }
        do {
            try store.save(list, defaultsRevision: defaultsRevision, declinedRevision: offered)
        } catch {
            return reply(.storageFailed, problems: [
                "The saved mute set couldn't be written, so nothing changed. \(error)"
            ])
        }
        declinedRevision = offered
        logger.log("\(caller, privacy: .public) declined default mute set revision \(offered).")
        return reply(.ok)
    }
    
    /// Work out what merging the current default set into the saved set would change, if the set is from an
    /// earlier revision. A merge that changes nothing just brings the revision up, saved with the next change. Call
    /// on ``queue``.
    func refreshUpdate() {
        pendingUpdate = nil
        guard state == .writable, let plan = MuteSetUpgrade.plan(for: list, revision: defaultsRevision) else { return }
        guard plan.merged != list else {
            defaultsRevision = MuteSet.currentRevision
            return
        }
        pendingUpdate = (plan.merged, MuteSetUpdate(from: list, to: plan.merged, after: plan.revision))
    }
}
