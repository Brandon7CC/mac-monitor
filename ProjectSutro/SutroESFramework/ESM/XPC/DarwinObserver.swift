//
//  DarwinObserver.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import OSLog
import notify


// MARK: - Darwin observer
/// Follows a Darwin notification until it's released, such as one the Security Extension posts.
///
/// Anyone can post a Darwin notification, so treat each one as a hint.
final class DarwinObserver {
    /// The registration, or `NOTIFY_TOKEN_INVALID` when it failed.
    private var token: Int32 = NOTIFY_TOKEN_INVALID

    /// Start following a notification. A registration that fails is logged, and nothing is called.
    ///
    /// - Parameters:
    ///   - name: The notification.
    ///   - queue: Where `handler` is called: the main queue, unless given.
    ///   - handler: Called for each post.
    init(_ name: String, queue: DispatchQueue = .main, handler: @escaping () -> Void) {
        let status = notify_register_dispatch(name, &token, queue) { _ in handler() }
        guard status != NOTIFY_STATUS_OK else { return }
        token = NOTIFY_TOKEN_INVALID
        Logger(subsystem: "com.swiftlydetecting.agent", category: "DarwinObserver")
            .error("Unable to register for \(name, privacy: .public): \(status)")
    }

    /// Stop following the notification.
    deinit {
        if token != NOTIFY_TOKEN_INVALID { notify_cancel(token) }
    }
}
