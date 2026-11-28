//
//  EventClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Event class
/// The lanes a capture session splits its subscriptions across: one Endpoint Security client per class of
/// ``endpointSecurity``, and the network lane, which no Endpoint Security client serves.
///
/// Endpoint Security hands each client its messages serially on the client's own queue, so the classes are handled in
/// parallel: a flood of file events no longer holds up process events. Which class serves an event is decided only by
/// ``EventClassTable``, from the category Apple's documentation files the event under.
public enum EventClass: String, CaseIterable, Codable, Sendable {
    /// Everything that isn't a file or memory event: process, interprocess, task port, IDs, code signing, sockets,
    /// kernel, pseudoterminal, and Apple's security events (XPC, login, BTM, TCC, XProtect, Open Directory, ...).
    case process
    /// File-system activity: most of the volume.
    case file
    /// Memory mapping: `mmap` and `mprotect`.
    case memory
    /// Mac Monitor's own network flows (``MacMonitorEvent``), read from the kernel's network statistics socket. They
    /// have no sequence numbers.
    case network

    /// The classes an Endpoint Security client serves, one client each, in order.
    public static let endpointSecurity: [EventClass] = [.process, .file, .memory]
}
