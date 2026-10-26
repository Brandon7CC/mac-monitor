//
//  EventClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Event class
/// The Endpoint Security clients a capture session splits its subscriptions across, one client per class.
///
/// Endpoint Security hands each client its messages serially on the client's own queue, so the classes are handled in
/// parallel: a flood of file events no longer holds up process events. Which class serves an event is decided only by
/// ``EventClassTable``, from the category Apple's documentation files the event under.
public enum EventClass: String, CaseIterable, Codable, Sendable {
    /// Everything that isn't a file or memory event: process, interprocess, task port, IDs, code signing, sockets,
    /// kernel, pseudoterminal, and Apple's security events (XPC, login, BTM, TCC, XProtect, Open Directory, …).
    case process
    /// File-system activity: most of the volume.
    case file
    /// Memory mapping: `mmap` and `mprotect`.
    case memory
}
