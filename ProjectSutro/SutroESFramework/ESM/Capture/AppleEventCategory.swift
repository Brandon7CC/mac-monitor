//
//  AppleEventCategory.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Apple's event categories
/// The categories Apple's Endpoint Security documentation files the event types under, by Apple's names.
///
/// Mac Monitor's `Events/Models` folders mirror these. Events Apple lists only as `es_events_t` members, with no
/// category (most of the security events added since macOS 13), are ``uncategorized``.
public enum AppleEventCategory: String, CaseIterable, Sendable {
    case fileSystem = "File-System Events"
    case fileMetadata = "File Metadata Events"
    case fileProvider = "File Provider Events"
    case link = "Symbolic Link (Link) Events"
    case fileSystemMounting = "File System Mounting Events"
    case memoryMapping = "Memory Mapping Events"
    case process = "Process Events"
    case interprocess = "Interprocess Events"
    case taskPort = "Task Port Events"
    case userAndGroupID = "User and Group ID Events"
    case codeSigning = "Code Signing Events"
    case socket = "Socket Events"
    case clock = "Clock Events"
    case kernel = "Kernel Events"
    case pseudoterminal = "Pseudoterminal Events"
    /// Listed by Apple only as `es_events_t` members: logins, Open Directory, BTM, TCC, XPC, authorization, and so on.
    case uncategorized = "No category"
    
    /// The client that serves this category's events.
    ///
    /// Apple's file and mount categories go to the file client and memory mapping to the memory client. Everything else
    /// goes to the process client: process and interprocess activity, task ports, credentials, code signing, the
    /// kernel, and every newer security event, which Apple leaves uncategorized.
    ///
    /// **Sockets:** `uipc_bind` and `uipc_connect` go to the process client. Apple files them under their own category,
    /// apart from the file-system events. They record which process binds or connects to which Unix domain socket
    /// (`docker.sock`, an ssh agent, `mDNSResponder`), so they're read with the exec, exit, and `xpc_connect` events of
    /// the same processes, and one client keeps Endpoint Security's order among them. They're rare next to file
    /// activity, and the three-client benchmark ran with them on the process client without a drop. Mutes apply to
    /// every client alike, so this choice changes no mute.
    public var eventClass: EventClass {
        switch self {
        case .fileSystem, .fileMetadata, .fileProvider, .link, .fileSystemMounting:
            return .file
        case .memoryMapping:
            return .memory
        case .socket:
            return .process
        case .process, .interprocess, .taskPort, .userAndGroupID, .codeSigning, .clock, .kernel, .pseudoterminal,
             .uncategorized:
            return .process
        }
    }
}


// MARK: - Event origin
/// Who creates an event, as `ESMessage.h` sorts them ("A note on userspace events").
public enum EventOrigin: String, Sendable {
    /// The kernel. Such events are mandatory: if no event was emitted, the operation didn't happen.
    case kernel
    /// A platform binary or framework. Such events are discretionary: Endpoint Security only promises them for the
    /// binary that ships with macOS, so a user's own `su` emits `setuid` but no `su` event.
    case userspace
}
