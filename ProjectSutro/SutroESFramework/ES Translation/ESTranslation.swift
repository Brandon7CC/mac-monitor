//
//  ESTranslation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/10/22.
//

import Foundation
import EndpointSecurity
import OSLog


private let dateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss.SSS"
    return formatter
}()


public func eventTimeStamp(for message: ESMessage) -> String {
    if let messageTime = message.message_darwin_time {
        return dateFormatter.string(from: messageTime)
    }
    return "Unknown timestamp"
}

public struct SelectableEvent: Identifiable, Hashable {
    public var id: UUID = UUID()
    public var selected: Bool
    public var es_event_type: es_event_type_t
    public var eventString: String
    
    public static func == (lhs: SelectableEvent, rhs: SelectableEvent) -> Bool {
        return lhs.eventString == rhs.eventString && lhs.selected == rhs.selected
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(eventString)
        hasher.combine(selected)
    }
}

// MARK: - Get events
public func getAllEventTypes() -> [String] {
    var allEventTypes: [String] = []
    // We're going to 64 here because there are 64 ES notify events and we're not starting at 0 because that's `ES_EVENT_TYPE_LAST`
    
    for index in 0..<Int(ES_EVENT_TYPE_LAST.rawValue) {
        let eventString: String = eventTypeToString(from: esEventTypeIDToEventType(eventID: index))
        allEventTypes.append(eventString)
    }
    return allEventTypes
}

// @discussion Returns all ES events
public func getAllEventTypesSelectable() -> [SelectableEvent] {
    var allSelectableEventTypes: [SelectableEvent] = []
    
    for index in 0..<Int(ES_EVENT_TYPE_LAST.rawValue) {
        allSelectableEventTypes.append(SelectableEvent(selected: false, es_event_type: esEventTypeIDToEventType(eventID: index), eventString: eventTypeToString(from: esEventTypeIDToEventType(eventID: index))))
    }
    return allSelectableEventTypes
}

// @discussion Returns only the supported / modeled ES events
public func getSupportedEventTypesSelectable() -> [SelectableEvent] {
    var supportedSelectableEvents: [SelectableEvent] = []
    
    // We're going to 64 here because there are 64 ES notify events and we're not starting at 0 because that's `ES_EVENT_TYPE_LAST`
    for rawEvent in supportedEvents {
        supportedSelectableEvents.append(SelectableEvent(selected: false, es_event_type: rawEvent, eventString: eventTypeToString(from: rawEvent)))
    }
    return supportedSelectableEvents
}


// Logs all ES event types and their IDs to the unified system log
public func osLogAllESEvents() {
    for index in 0..<Int(ES_EVENT_TYPE_LAST.rawValue) {
        os_log("ES Event Type: (\(eventTypeToString(from: esEventTypeIDToEventType(eventID: index)))) --> Index: (\(index))")
    }
}


public func eventStringToImage(from eventString: String) -> String {
    switch(eventString) {
    case "ES_EVENT_TYPE_NOTIFY_EXEC":
        return "cpu"
    case "ES_EVENT_TYPE_NOTIFY_FORK":
        return "point.topleft.down.curvedto.point.bottomright.up"
    case "ES_EVENT_TYPE_NOTIFY_EXIT":
        return "eject.fill"
    case "ES_EVENT_TYPE_NOTIFY_CREATE":
        return "doc.plaintext"
    case "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR":
        return "delete.backward.fill"
    case "ES_EVENT_TYPE_NOTIFY_MMAP":
        return "memorychip"
    case "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD":
        return "lock.doc"
    case "ES_EVENT_TYPE_NOTIFY_DUP":
        return "folder.badge.plus"
    case "ES_EVENT_TYPE_NOTIFY_MOUNT":
        return "mount"
    case "ES_EVENT_TYPE_NOTIFY_RENAME":
        return "filemenu.and.cursorarrow"
    case "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN":
        return "macwindow.badge.plus"
    case "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK":
        return "lock.open"
    case "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN":
        return "person.fill.checkmark"
    case "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED":
        return "bolt.shield"
    case "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED":
        return "checkmark.shield"
    case "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE":
        return "lock.doc"
    case "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN":
        return "network"
    case "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT":
        return "network"
    case "ES_EVENT_TYPE_NOTIFY_UNLINK":
        return "trash"
    case "ES_EVENT_TYPE_NOTIFY_OPEN":
        return "envelope.open.fill"
    case "ES_EVENT_TYPE_NOTIFY_WRITE":
        return "square.and.pencil"
    case "ES_EVENT_TYPE_NOTIFY_LINK":
        return "link.badge.plus"
    case "ES_EVENT_TYPE_NOTIFY_CLOSE":
        return "xmark.square"
    case "ES_EVENT_TYPE_NOTIFY_SIGNAL":
        return "dot.radiowaves.forward"
    case "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE":
        return "bolt.horizontal.fill"
    case "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN":
        return "captions.bubble"
    case "ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED":
        return "signature"
    case "ES_EVENT_TYPE_NOTIFY_SETEXTATTR":
        return "filemenu.and.selection"
    case "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME":
        return "autostartstop.trianglebadge.exclamationmark"
    case "ES_EVENT_TYPE_NOTIFY_TRACE":
        return "stethoscope"
    case "ES_EVENT_TYPE_NOTIFY_GET_TASK":
        return "creditcard.trianglebadge.exclamationmark"
    case "ES_EVENT_TYPE_NOTIFY_PROC_CHECK":
        return "barcode.viewfinder"
    
    // MARK: - macOS 14+ events
    case "ES_EVENT_TYPE_NOTIFY_PROFILE_ADD":  // Profile add
        return "magazine"
    case "ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER":  // Open Directory Create User
        return "person.fill.badge.plus"
    case "ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD":  // Open Directory Modify Password
        return "rectangle.and.pencil.and.ellipsis"
    case "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET":   // Open Directory Attibute Set
        return "slider.horizontal.2.square.on.square"
    case "ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER":   // Open Directory Disable User
        return "person.crop.circle.badge.minus"
    case "ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD":  // Open Directory Group Add
        return "person.3.fill"
    case "ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP":  // Open Directory Group Create
        return "person.3.fill"
    case "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD":  // Open Directory attribute value add
        return "text.badge.plus"
    case "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT":
        return "phone.connection.fill"
    case "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION":
        return "questionmark.diamond"
    case "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT":
        return "arrowshape.right.fill"
    
    // MARK: - macOS 15+ events
    case "ES_EVENT_TYPE_NOTIFY_TCC_MODIFY":
        return "hand.raised.fill"
    case "ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE":
        return "shield.lefthalf.filled.trianglebadge.exclamationmark"
    default:
        os_log("❌ Unknown image for event: \(eventString)")
        return "questionmark.app.dashed"
    }
}


// MARK: - ES muting
public func getMuteCaseString(muteType: es_mute_path_type_t) -> String {
    switch(muteType) {
    case ES_MUTE_PATH_TYPE_PREFIX:
        return "ES_MUTE_PATH_TYPE_PREFIX"
    case ES_MUTE_PATH_TYPE_LITERAL:
        return "ES_MUTE_PATH_TYPE_LITERAL"
    case ES_MUTE_PATH_TYPE_TARGET_PREFIX:
        return "ES_MUTE_PATH_TYPE_TARGET_PREFIX"
    case ES_MUTE_PATH_TYPE_TARGET_LITERAL:
        return "ES_MUTE_PATH_TYPE_TARGET_LITERAL"
    default:
        return "ES_MUTE_PATH_TYPE_TARGET_PREFIX"
    }
}

public func getMuteCaseFromString(muteString: String) -> es_mute_path_type_t {
    switch(muteString) {
    case "ES_MUTE_PATH_TYPE_PREFIX":
        return ES_MUTE_PATH_TYPE_PREFIX
    case "ES_MUTE_PATH_TYPE_LITERAL":
        return ES_MUTE_PATH_TYPE_LITERAL
    case "ES_MUTE_PATH_TYPE_TARGET_PREFIX":
        return ES_MUTE_PATH_TYPE_TARGET_PREFIX
    case "ES_MUTE_PATH_TYPE_TARGET_LITERAL":
        return ES_MUTE_PATH_TYPE_TARGET_LITERAL
    default:
        return ES_MUTE_PATH_TYPE_TARGET_PREFIX
    }
}
