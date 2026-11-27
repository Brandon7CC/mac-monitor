//
//  EventType+Accessors.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//

import Foundation

extension EventType {
    /// The exec and fork payloads, for `ESManager.shouldInsert(_:droppingPlatformBinaries:)` and
    /// ``ESMessage/denormalize(from:)``.
    var exec: ProcessExecEvent? { if case .exec(let e) = self { e } else { nil } }
    var fork: ProcessForkEvent? { if case .fork(let e) = self { e } else { nil } }

    /// Payloads the tests read.
    var mount: MountEvent? { if case .mount(let e) = self { e } else { nil } }
    var mprotect: MProtectEvent? { if case .mprotect(let e) = self { e } else { nil } }
    var iokit_open: IOKitOpenEvent? { if case .iokit_open(let e) = self { e } else { nil } }
    var mmap: MMapEvent? { if case .mmap(let e) = self { e } else { nil } }
    var close: FileCloseEvent? { if case .close(let e) = self { e } else { nil } }
    var authentication: AuthenticationEvent? { if case .authentication(let e) = self { e } else { nil } }
    var remote_thread_create: RemoteThreadCreateEvent? {
        if case .remote_thread_create(let e) = self { e } else { nil }
    }
}


// MARK: - Mac Monitor's own events
extension EventType {
    /// The Mac Monitor event it is, or `nil` for an Endpoint Security event.
    public var macMonitorEvent: MacMonitorEvent? {
        switch self {
        case .new_flow: .new_flow
        case .flow_closed: .flow_closed
        default: nil
        }
    }

    /// Is it a network flow, whose record is Mac Monitor's own? Copies no payload.
    public var isNetworkFlow: Bool { macMonitorEvent != nil }

    /// A network flow's payload, or `nil` for any other event.
    public var networkFlow: NetworkFlowEvent? {
        switch self {
        case .new_flow(let flow), .flow_closed(let flow): flow
        default: nil
        }
    }
}

