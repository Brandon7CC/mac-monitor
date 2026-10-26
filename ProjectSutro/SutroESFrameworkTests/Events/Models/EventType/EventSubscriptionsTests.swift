//
//  EventSubscriptionsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Event subscriptions
/// Pins which events Mac Monitor offers and subscribes to, and that each has its own icon.
final class EventSubscriptionsTests: XCTestCase {
    /// The icon ``eventStringToImage(from:)`` gives an event it doesn't know.
    private static let unknownEventIcon = "questionmark.app.dashed"

    /// Every macOS version that changes which events Mac Monitor offers, and one long after.
    private static let gates = [(13, 0), (14, 0), (15, 0), (15, 4), (27, 0)]
        .map { OperatingSystemVersion(majorVersion: $0, minorVersion: $1, patchVersion: 0) }

    /// Every Open Directory event Mac Monitor records is offered and subscribed to by default from macOS 14, as
    /// `od_group_remove` wasn't.
    func testOpenDirectoryEvents() {
        for event in RawMessageFixture.openDirectoryEvents.map(\.type) {
            XCTAssertTrue(supportedEvents.contains(event), eventTypeToString(from: event))
            XCTAssertTrue(defaultEventSubscriptions.contains(event), eventTypeToString(from: event))
        }
    }

    /// Every event offered has its own icon.
    func testEveryEventHasAnIcon() {
        for event in supportedEvents {
            let name = eventTypeToString(from: event)
            XCTAssertNotEqual(eventStringToImage(from: name), Self.unknownEventIcon, name)
        }
    }

    /// Every event offered is a NOTIFY event Mac Monitor names, offered once: a capture session subscribes only to
    /// these.
    func testSupportedEventsAreNotifyOnly() {
        for event in supportedEvents {
            let name = eventTypeToString(from: event)
            XCTAssertTrue(name.hasPrefix("ES_EVENT_TYPE_NOTIFY_"), name)
            XCTAssertNotEqual(event, ES_EVENT_TYPE_LAST, name)
        }
        XCTAssertEqual(Set(supportedEvents.map(\.rawValue)).count, supportedEvents.count)
        XCTAssertEqual(Set(defaultEventSubscriptions.map(\.rawValue)).count, defaultEventSubscriptions.count)
    }

    /// ``ModeledEvent/all`` offers, on each macOS that changes them, the events the hand lists did, in their order,
    /// and this Mac's are ``supportedEvents``.
    func testSupportedEventsMatchTheHandListsOnEachMacOS() {
        for os in Self.gates {
            let offered = ModeledEvent.all.filter { $0.since.map { Self.isAtLeast(os, $0) } ?? true }.map(\.type)
            XCTAssertEqual(Self.names(offered), Self.names(Self.handLists(on: os).supported), "\(os)")
        }
        let thisMac = Self.handLists(on: ProcessInfo.processInfo.operatingSystemVersion)
        XCTAssertEqual(Self.names(supportedEvents), Self.names(thisMac.supported))
    }

    /// ``ModeledEvent/all`` subscribes by default, on each macOS that changes them, to the events the hand lists did,
    /// and this Mac's are ``defaultEventSubscriptions``.
    func testDefaultSubscriptionsMatchTheHandListsOnEachMacOS() {
        for os in Self.gates {
            let defaults = ModeledEvent.all.filter { $0.isDefault && $0.since.map { Self.isAtLeast(os, $0) } ?? true }
            XCTAssertEqual(Set(Self.names(defaults.map(\.type))), Set(Self.names(Self.handLists(on: os).defaults)),
                           "\(os)")
        }
        let thisMac = Self.handLists(on: ProcessInfo.processInfo.operatingSystemVersion)
        XCTAssertEqual(Set(Self.names(defaultEventSubscriptions)), Set(Self.names(thisMac.defaults)))
        XCTAssertEqual(defaultEventSubscriptions.count, thisMac.defaults.count)
    }

    /// Every event name, and two Mac Monitor doesn't know, shows the icon the `switch` gave it before
    /// ``ModeledEvent/symbols``.
    func testIconsMatchTheSwitch() {
        for name in esEventTypeNames + ["ES_EVENT_TYPE_LAST", ""] {
            XCTAssertEqual(eventStringToImage(from: name), Self.switchIcons[name] ?? Self.unknownEventIcon, name)
        }
        XCTAssertEqual(ModeledEvent.symbols.count, Self.switchIcons.count)
    }
}


// MARK: - Frozen copies
private extension EventSubscriptionsTests {
    /// The events offered on every macOS, as the hand list gave them.
    static let coreEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, ES_EVENT_TYPE_NOTIFY_DUP,
        ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, ES_EVENT_TYPE_NOTIFY_TRACE, ES_EVENT_TYPE_NOTIFY_GET_TASK,
        ES_EVENT_TYPE_NOTIFY_PROC_CHECK, ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
        ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, ES_EVENT_TYPE_NOTIFY_UIPC_BIND
    ]

    /// The core events subscribed to by default, as the hand list gave them.
    static let coreDefaults: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
        ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
        ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_NOTIFY_TRACE, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_PTY_GRANT, ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
        ES_EVENT_TYPE_NOTIFY_LINK
    ]

    /// The events macOS 14 adds, offered and subscribed to by default, as the hand list gave them.
    static let sonomaEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD,
        ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
        ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD, ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION, ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
        ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP
    ]

    /// The icon each event name got from the `switch`, which had no others.
    static let switchIcons = [
        "ES_EVENT_TYPE_NOTIFY_EXEC": "cpu",
        "ES_EVENT_TYPE_NOTIFY_FORK": "point.topleft.down.curvedto.point.bottomright.up",
        "ES_EVENT_TYPE_NOTIFY_EXIT": "eject.fill",
        "ES_EVENT_TYPE_NOTIFY_CREATE": "doc.plaintext",
        "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR": "delete.backward.fill",
        "ES_EVENT_TYPE_NOTIFY_MMAP": "memorychip",
        "ES_EVENT_TYPE_NOTIFY_MPROTECT": "staroflife.shield",
        "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD": "lock.doc",
        "ES_EVENT_TYPE_NOTIFY_DUP": "folder.badge.plus",
        "ES_EVENT_TYPE_NOTIFY_MOUNT": "mount",
        "ES_EVENT_TYPE_NOTIFY_RENAME": "filemenu.and.cursorarrow",
        "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN": "macwindow.badge.plus",
        "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK": "lock.open",
        "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN": "person.fill.checkmark",
        "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED": "bolt.shield",
        "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED": "checkmark.shield",
        "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE": "lock.doc",
        "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN": "network",
        "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT": "network",
        "ES_EVENT_TYPE_NOTIFY_UNLINK": "trash",
        "ES_EVENT_TYPE_NOTIFY_OPEN": "envelope.open.fill",
        "ES_EVENT_TYPE_NOTIFY_WRITE": "square.and.pencil",
        "ES_EVENT_TYPE_NOTIFY_LINK": "link.badge.plus",
        "ES_EVENT_TYPE_NOTIFY_CLOSE": "xmark.square",
        "ES_EVENT_TYPE_NOTIFY_SIGNAL": "dot.radiowaves.forward",
        "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE": "bolt.horizontal.fill",
        "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN": "captions.bubble",
        "ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED": "signature",
        "ES_EVENT_TYPE_NOTIFY_SETEXTATTR": "filemenu.and.selection",
        "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME": "autostartstop.trianglebadge.exclamationmark",
        "ES_EVENT_TYPE_NOTIFY_TRACE": "stethoscope",
        "ES_EVENT_TYPE_NOTIFY_GET_TASK": "creditcard.trianglebadge.exclamationmark",
        "ES_EVENT_TYPE_NOTIFY_PROC_CHECK": "barcode.viewfinder",
        "ES_EVENT_TYPE_NOTIFY_SETMODE": "plus.diamond",
        "ES_EVENT_TYPE_NOTIFY_PTY_GRANT": "apple.terminal",
        "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT": "line.diagonal.trianglehead.up.right.left.down",
        "ES_EVENT_TYPE_NOTIFY_UIPC_BIND": "line.diagonal.trianglehead.up.right",
        "ES_EVENT_TYPE_NOTIFY_PROFILE_ADD": "magazine",
        "ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER": "person.fill.badge.plus",
        "ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD": "rectangle.and.pencil.and.ellipsis",
        "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET": "slider.horizontal.2.square.on.square",
        "ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER": "person.crop.circle.badge.minus",
        "ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD": "person.3.fill",
        "ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE": "person.fill.badge.minus",
        "ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP": "person.3.fill",
        "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD": "text.badge.plus",
        "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT": "phone.connection.fill",
        "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION": "questionmark.diamond",
        "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT": "arrowshape.right.fill",
        "ES_EVENT_TYPE_NOTIFY_GETEXTATTR": "text.viewfinder",
        "ES_EVENT_TYPE_NOTIFY_LISTEXTATTR": "list.bullet.indent",
        "ES_EVENT_TYPE_NOTIFY_TCC_MODIFY": "hand.raised.fill",
        "ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE": "shield.lefthalf.filled.trianglebadge.exclamationmark"
    ]

    /// The events the hand lists offered, and subscribed to by default, on a macOS version.
    ///
    /// - Parameter os: The macOS version.
    /// - Returns: The core events, then those of macOS 14, Gatekeeper's override from macOS 15, and TCC's modify
    ///   from macOS 15.4, offered and by default.
    static func handLists(on os: OperatingSystemVersion) -> (supported: [es_event_type_t],
                                                              defaults: [es_event_type_t]) {
        let tccModify = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
        let added = (isAtLeast(os, sonoma) ? sonomaEvents : [])
            + (isAtLeast(os, sequoia) ? [ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE] : [])
            + (isAtLeast(os, tccModify) ? [ES_EVENT_TYPE_NOTIFY_TCC_MODIFY] : [])
        return (coreEvents + added, coreDefaults + added)
    }

    /// Is one macOS version at least another, as `ProcessInfo.isOperatingSystemAtLeast(_:)` compares them?
    ///
    /// - Parameters:
    ///   - os: The version running.
    ///   - version: The version needed.
    /// - Returns: `true` if `os` is `version` or later.
    static func isAtLeast(_ os: OperatingSystemVersion, _ version: OperatingSystemVersion) -> Bool {
        (os.majorVersion, os.minorVersion, os.patchVersion)
            >= (version.majorVersion, version.minorVersion, version.patchVersion)
    }

    /// Names event types, so a failure says which.
    ///
    /// - Parameter events: The event types.
    /// - Returns: Their `ESTypes.h` names, in order.
    static func names(_ events: [es_event_type_t]) -> [String] {
        events.map { eventTypeToString(from: $0) }
    }
}
