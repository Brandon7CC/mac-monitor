//
//  EventSubscriptions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/12/23.
//

import Foundation

/// macOS 14.0 Sonoma version
///
/// Used to determine event availability
let sonoma = OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
/// macOS 15.0 Sequoia version
let sequoia = OperatingSystemVersion(majorVersion: 15, minorVersion: 0, patchVersion: 0)
/// macOS 15.4, the first to deliver `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY`
let sequoia15_4 = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)


// MARK: - Modeled events
/// An Endpoint Security event Mac Monitor models. ``all`` is the one place that says which events Mac Monitor offers
/// (``supportedEvents``), which it subscribes to on first launch (``defaultEventSubscriptions``), from which macOS,
/// and which icon each one shows (``eventStringToImage(from:)``).
struct ModeledEvent {
    /// The event type.
    let type: es_event_type_t
    /// Its SF Symbol.
    let symbol: String
    /// The first macOS that delivers it, or `nil` for every macOS Mac Monitor runs on.
    let since: OperatingSystemVersion?
    /// Whether Mac Monitor subscribes to it on first launch.
    let isDefault: Bool

    /// Whether this Mac delivers it.
    var isAvailable: Bool { since.map(ProcessInfo.processInfo.isOperatingSystemAtLeast) ?? true }

    /// Describes an event Mac Monitor models.
    ///
    /// - Parameters:
    ///   - type: The event type.
    ///   - symbol: Its SF Symbol.
    ///   - since: The first macOS that delivers it, or `nil` for every macOS Mac Monitor runs on.
    ///   - isDefault: Whether Mac Monitor subscribes to it on first launch.
    init(_ type: es_event_type_t, _ symbol: String, since: OperatingSystemVersion? = nil, isDefault: Bool = false) {
        (self.type, self.symbol, self.since, self.isDefault) = (type, symbol, since, isDefault)
    }

    /// Every event Mac Monitor models, in the order it offers them: the events of every macOS it runs on, then those
    /// macOS 14 adds, then those macOS 15 adds.
    static let all: [ModeledEvent] = [
        .init(ES_EVENT_TYPE_NOTIFY_EXEC, "cpu", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_FORK, "point.topleft.down.curvedto.point.bottomright.up", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_EXIT, "eject.fill", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_CREATE, "doc.plaintext", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_MMAP, "memorychip", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_MPROTECT, "staroflife.shield"),
        .init(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, "lock.doc", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, "lock.doc", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "network", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "network"),
        .init(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "bolt.shield", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "checkmark.shield", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_MOUNT, "mount", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "person.fill.checkmark", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "macwindow.badge.plus"),
        .init(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "lock.open", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_DUP, "folder.badge.plus"),
        .init(ES_EVENT_TYPE_NOTIFY_RENAME, "filemenu.and.cursorarrow", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_UNLINK, "trash"),
        .init(ES_EVENT_TYPE_NOTIFY_OPEN, "envelope.open.fill"),
        .init(ES_EVENT_TYPE_NOTIFY_WRITE, "square.and.pencil"),
        .init(ES_EVENT_TYPE_NOTIFY_LINK, "link.badge.plus", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_CLOSE, "xmark.square"),
        .init(ES_EVENT_TYPE_NOTIFY_SIGNAL, "dot.radiowaves.forward"),
        .init(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "bolt.horizontal.fill", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "captions.bubble", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, "signature", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "autostartstop.trianglebadge.exclamationmark"),
        .init(ES_EVENT_TYPE_NOTIFY_TRACE, "stethoscope", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_GET_TASK, "creditcard.trianglebadge.exclamationmark"),
        .init(ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "barcode.viewfinder"),
        .init(ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "delete.backward.fill", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "filemenu.and.selection"),
        .init(ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "text.viewfinder"),
        .init(ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "list.bullet.indent"),
        .init(ES_EVENT_TYPE_NOTIFY_SETMODE, "plus.diamond", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "apple.terminal", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "line.diagonal.trianglehead.up.right.left.down", isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "line.diagonal.trianglehead.up.right", isDefault: true),
        // macOS 14 and later
        .init(ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, "magazine", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, "person.fill.badge.plus", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, "person.3.fill", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, "person.fill.badge.minus", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD, "rectangle.and.pencil.and.ellipsis", since: sonoma,
              isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD, "text.badge.plus", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, "phone.connection.fill", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION, "questionmark.diamond", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT, "arrowshape.right.fill", since: sonoma, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP, "person.3.fill", since: sonoma, isDefault: true),
        // macOS 15 and later
        .init(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, "shield.lefthalf.filled.trianglebadge.exclamationmark",
              since: sequoia, isDefault: true),
        .init(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "hand.raised.fill", since: sequoia15_4, isDefault: true)
    ]

    /// Each modeled event's SF Symbol by its `ESTypes.h` name, with those of the two Open Directory events Mac
    /// Monitor names but doesn't model.
    static let symbols = Dictionary(uniqueKeysWithValues: all.map { (eventTypeToString(from: $0.type), $0.symbol) })
        .merging(["ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET": "slider.horizontal.2.square.on.square",
                  "ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER": "person.crop.circle.badge.minus"]) { modeled, _ in modeled }
}

/// All the Endpoint Security events supported by Mac Monitor on this Mac, in ``ModeledEvent/all``'s order
public var supportedEvents: [es_event_type_t] { ModeledEvent.all.filter(\.isAvailable).map(\.type) }

/// The default event subscriptions for Mac Monitor
///
/// The ``supportedEvents`` this Mac delivers that Mac Monitor subscribes to on first launch
/// (``ModeledEvent/isDefault``), in ``ModeledEvent/all``'s order.
public var defaultEventSubscriptions: [es_event_type_t] {
    ModeledEvent.all.filter { $0.isAvailable && $0.isDefault }.map(\.type)
}
