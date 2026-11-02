//
//  EventType+Accessors.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//

import Foundation

extension EventType {
    /// The exec and fork payloads, for `ESManager.shouldInsert(_:)` and ``ESMessage/denormalize(from:)``.
    var exec: ProcessExecEvent? { if case .exec(let e) = self { e } else { nil } }
    var fork: ProcessForkEvent? { if case .fork(let e) = self { e } else { nil } }

    /// Payloads the tests read.
    var mount: MountEvent? { if case .mount(let e) = self { e } else { nil } }
    var mprotect: MProtectEvent? { if case .mprotect(let e) = self { e } else { nil } }
    var remote_thread_create: RemoteThreadCreateEvent? {
        if case .remote_thread_create(let e) = self { e } else { nil }
    }
}
