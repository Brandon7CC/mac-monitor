//
//  EventClassTableTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Event class table
/// Pins the table that splits capture across Endpoint Security clients: every event Mac Monitor names is filed under
/// exactly one of Apple's categories, each category goes to one client, and the header's userspace events agree.
final class EventClassTableTests: XCTestCase {
    /// Every NOTIFY event Mac Monitor names, as `allESEvents` lists them.
    private var namedNotifyEvents: [es_event_type_t] {
        allESEvents.filter { eventTypeToString(from: $0).hasPrefix("ES_EVENT_TYPE_NOTIFY_") }
    }
    
    /// Every event listed by the categories, in order, duplicates included.
    private var listedEvents: [es_event_type_t] {
        EventClassTable.categories.flatMap(\.events)
    }
    
    /// Asserts each event's client and category.
    ///
    /// - Parameters:
    ///   - events: The events.
    ///   - eventClass: The client each should go to.
    ///   - category: The category each should be filed under.
    ///   - line: The caller's line.
    private func assertClass(_ events: [es_event_type_t], go eventClass: EventClass,
                             as category: AppleEventCategory, line: UInt = #line) {
        for event in events {
            let name = eventTypeToString(from: event)
            XCTAssertEqual(EventClassTable.category(of: event), category, name, line: line)
            XCTAssertEqual(EventClassTable.eventClass(of: event), eventClass, name, line: line)
        }
    }
    
    /// Each NOTIFY event in `allESEvents` is in exactly one category, and nothing else is listed.
    func testEveryNamedNotifyEventIsListedOnce() {
        let listed = listedEvents.map(\.rawValue)
        XCTAssertEqual(listed.count, Set(listed).count, "An event is listed twice")
        XCTAssertEqual(Set(listed), Set(namedNotifyEvents.map(\.rawValue)))
        XCTAssertEqual(listed.count, 104)
    }
    
    /// Every event Mac Monitor can subscribe to is listed by name rather than classed by the fallback.
    func testEverySupportedEventIsListed() {
        for event in supportedEvents {
            XCTAssertTrue(EventClassTable.lists(event), eventTypeToString(from: event))
        }
        for event in defaultEventSubscriptions {
            XCTAssertTrue(supportedEvents.contains(event), eventTypeToString(from: event))
        }
    }
    
    /// Apple's file and mount categories go to the file client, memory mapping to the memory client, and the rest to
    /// the process client, sockets included.
    func testCategoriesMapToClients() {
        let file: Set<AppleEventCategory> = [.fileSystem, .fileMetadata, .fileProvider, .link, .fileSystemMounting]
        for category in AppleEventCategory.allCases {
            let expected: EventClass = file.contains(category) ? .file : category == .memoryMapping ? .memory : .process
            XCTAssertEqual(category.eventClass, expected, category.rawValue)
        }
        XCTAssertEqual(AppleEventCategory.socket.eventClass, .process)
        XCTAssertEqual(Set(EventClassTable.categories.map(\.category)), Set(AppleEventCategory.allCases))
    }
    
    /// The events Mac Monitor captures most go where Apple's categories put them.
    func testPinnedAssignments() {
        assertClass([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_WRITE,
                     ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_DUP],
                    go: .file, as: .fileSystem)
        assertClass([ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_NOTIFY_LISTEXTATTR,
                     ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_NOTIFY_SETMODE],
                    go: .file, as: .fileMetadata)
        assertClass([ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_UNLINK], go: .file, as: .link)
        assertClass([ES_EVENT_TYPE_NOTIFY_MOUNT], go: .file, as: .fileSystemMounting)
        assertClass([ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT], go: .memory, as: .memoryMapping)
        assertClass([ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
                     ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_NOTIFY_PROC_CHECK],
                    go: .process, as: .process)
        assertClass([ES_EVENT_TYPE_NOTIFY_TRACE, ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
                     ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME],
                    go: .process, as: .interprocess)
        assertClass([ES_EVENT_TYPE_NOTIFY_GET_TASK], go: .process, as: .taskPort)
        assertClass([ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED], go: .process, as: .codeSigning)
        assertClass([ES_EVENT_TYPE_NOTIFY_UIPC_BIND, ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT], go: .process, as: .socket)
        assertClass([ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN], go: .process, as: .kernel)
        assertClass([ES_EVENT_TYPE_NOTIFY_PTY_GRANT], go: .process, as: .pseudoterminal)
        let security = namedNotifyEvents.filter { event in
            let name = eventTypeToString(from: event)
            return ["_OD_", "_BTM_", "_LOGIN_", "_LW_SESSION_", "_OPENSSH_", "_XP_MALWARE_", "_AUTHORIZATION_"]
                .contains { name.contains($0) }
        }
        XCTAssertEqual(security.count, 27)
        assertClass(security + [ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
                                ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, ES_EVENT_TYPE_NOTIFY_PROFILE_ADD],
                    go: .process, as: .uncategorized)
    }
    
    /// The 38 NOTIFY events `ESMessage.h` says userspace creates are userspace, the rest kernel, and the two Apple
    /// sources agree: a userspace event is a File Provider or an uncategorized one, and every uncategorized event but
    /// `xpc_connect` comes from userspace.
    func testOriginsFollowESMessageHeader() {
        let userspace = Set(EventClassTable.userspaceEvents.map(\.rawValue))
        XCTAssertEqual(EventClassTable.userspaceEvents.count, 38)
        XCTAssertEqual(userspace.count, 38)
        for event in namedNotifyEvents {
            let name = eventTypeToString(from: event)
            let category = EventClassTable.category(of: event)
            let origin = EventClassTable.origin(of: event)
            XCTAssertEqual(origin, userspace.contains(event.rawValue) ? .userspace : .kernel, name)
            if origin == .userspace {
                XCTAssertTrue([.uncategorized, .fileProvider].contains(category), name)
            }
            if category == .uncategorized, event != ES_EVENT_TYPE_NOTIFY_XPC_CONNECT {
                XCTAssertEqual(origin, .userspace, name)
            }
        }
        XCTAssertEqual(EventClassTable.origin(of: ES_EVENT_TYPE_NOTIFY_XPC_CONNECT), .kernel)
        XCTAssertEqual(EventClassTable.origin(of: ES_EVENT_TYPE_NOTIFY_EXEC), .kernel)
    }
    
    /// An event the table doesn't list, such as one a newer SDK adds (macOS 27's `bootstrap_check_in` and
    /// `bootstrap_look_up`), is uncategorized, so it goes to the process client.
    func testUnlistedEventsFallBackToTheProcessClient() {
        let newer = (ES_EVENT_TYPE_NOTIFY_TCC_MODIFY.rawValue + 1...ES_EVENT_TYPE_LAST.rawValue)
            .map { es_event_type_t(rawValue: $0) }
        for event in newer {
            XCTAssertFalse(EventClassTable.lists(event), "\(event.rawValue)")
            XCTAssertEqual(EventClassTable.category(of: event), .uncategorized, "\(event.rawValue)")
            XCTAssertEqual(EventClassTable.eventClass(of: event), .process, "\(event.rawValue)")
            XCTAssertEqual(EventClassTable.origin(of: event), .kernel, "\(event.rawValue)")
        }
        XCTAssertTrue(newer.contains(ES_EVENT_TYPE_LAST))
    }
    
    /// Splitting the default subscriptions gives each client its own events, in their order, and loses none.
    ///
    /// - Throws: `XCTSkip` before macOS 14, whose defaults have no events for some clients' share to check against.
    func testSplitKeepsOrderAndCoversEveryEvent() throws {
        try XCTSkipUnless(ProcessInfo().isOperatingSystemAtLeast(sonoma), "The defaults grow from macOS 14")
        let events = defaultEventSubscriptions
        let split = EventClassTable.split(events)
        XCTAssertEqual(Set(split.keys), Set(EventClass.allCases))
        XCTAssertEqual(split.values.map(\.count).reduce(0, +), events.count)
        for (eventClass, share) in split {
            XCTAssertEqual(share.map(\.rawValue), events.filter { EventClassTable.eventClass(of: $0) == eventClass }
                .map(\.rawValue), eventClass.rawValue)
        }
        XCTAssertEqual(split[.memory]?.map(\.rawValue), [ES_EVENT_TYPE_NOTIFY_MMAP.rawValue])
        XCTAssertTrue(EventClassTable.split([]).isEmpty)
    }
}
