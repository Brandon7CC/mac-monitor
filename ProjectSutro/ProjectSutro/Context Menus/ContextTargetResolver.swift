//
//  ContextTargetResolver.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/22/23.
//

import Foundation
import SutroESFramework
import EndpointSecurity


public class IntelligentEventTargeting {
    // MARK: File events
    public static func isEventFileClass(es_event: es_event_type_t) -> Bool {
        switch(es_event) {
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            return true
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            return true
        case ES_EVENT_TYPE_NOTIFY_DUP:
            return true
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            return true
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return true
        case ES_EVENT_TYPE_NOTIFY_LINK:
            return true
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            return true
        default:
            // By default an event should not be target by a parent dir
            return false
        }
    }
    
    // MARK: Parent dir
    // @discussion it doesn't make sense to mute the `target_path` for all types of events. In some cases
    //             the user might not want to mute a file for example, but the directory being written to.
    public static func targetShouldBeParentDir(esEventType: String) -> Bool {
        let es_event: es_event_type_t = eventStringToType(from: esEventType)
        if isEventFileClass(es_event: es_event) {
            return true
        }
        
        switch es_event {
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            return true
        default:
            return false
        }
    }

    // MARK: Menu target
    /// What an event's menu filters or mutes for its target path: the target's folder, ending in exactly one "/", for
    /// the events that use the folder (``targetShouldBeParentDir(esEventType:)``), so `/a/b/` never matches `/a/bc`.
    /// Otherwise, or when the folder would be "/" (which matches every path) or there is none, the target path itself.
    ///
    /// - Parameters:
    ///   - targetPath: The event's target path.
    ///   - esEventType: The event's `ES_EVENT_TYPE_*` name.
    /// - Returns: The path to filter or mute, and whether it's the target's folder.
    public static func menuTarget(of targetPath: String, esEventType: String) -> (path: String, isFolder: Bool) {
        guard targetShouldBeParentDir(esEventType: esEventType) else { return (targetPath, false) }
        let folder = targetPath.deletingLastPathComponent
        guard !folder.isEmpty, folder != "/" else { return (targetPath, false) }
        return (folder.hasSuffix("/") ? folder : folder + "/", true)
    }
}

