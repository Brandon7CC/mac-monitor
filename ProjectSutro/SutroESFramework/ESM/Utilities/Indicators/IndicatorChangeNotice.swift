//
//  IndicatorChangeNotice.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import Combine
import notify


// MARK: - Announcing changes
public extension SavedIndicatorSet {
    /// Post a Darwin notification after each change to the set, whoever made it, while the subscription is held
    /// (Security Extension context). Mac Monitor asks for the set again when it sees one (``IndicatorChangeNotice``).
    ///
    /// - Parameter name: The notification: ``SensorXPC/indicatorsChangedNotification`` in the Security Extension.
    /// - Returns: The subscription, which stops the posts once it's released.
    func announceChanges(as name: String) -> AnyCancellable {
        follow { _ in notify_post(name) }.1
    }
}


// MARK: - Change notice
/// Follows the Darwin notification the Security Extension posts after each change to the Mac's indicator set (agent
/// context), and calls back on the main queue at most once an interval for it.
///
/// The first post calls back at once. One that comes sooner waits for the rest of the interval, and any more join it,
/// so the last change is always asked for. Anyone can post a Darwin notification, so it's only a hint: the set comes
/// over the connection that verifies the Security Extension's code signature, and a flood of posts costs one request
/// an interval.
final class IndicatorChangeNotice {
    /// The least time between calls.
    private let interval: DispatchTimeInterval
    /// Called on the main queue for each change.
    private let changed: () -> Void
    /// When the last call was made.
    private var last: DispatchTime?
    /// Is a call waiting for the rest of the interval?
    private var isWaiting = false
    /// Follows the notification while the notice lives.
    private var observer: DarwinObserver?

    /// - Parameters:
    ///   - name: The notification.
    ///   - interval: The least time between calls: a second, unless a test passes its own.
    ///   - changed: Called on the main queue.
    init(name: String, interval: DispatchTimeInterval = .seconds(1), changed: @escaping () -> Void) {
        self.interval = interval
        self.changed = changed
        observer = DarwinObserver(name) { [weak self] in self?.notified() }
    }

    /// Call back now, or once the interval since the last call has passed. Call on the main queue.
    func notified() {
        guard !isWaiting else { return }
        guard let due = last.map({ $0 + interval }), due > .now() else { return call() }
        isWaiting = true
        DispatchQueue.main.asyncAfter(deadline: due) { [weak self] in
            self?.isWaiting = false
            self?.call()
        }
    }

    /// Call back, and note when.
    private func call() {
        last = .now()
        changed()
    }
}
