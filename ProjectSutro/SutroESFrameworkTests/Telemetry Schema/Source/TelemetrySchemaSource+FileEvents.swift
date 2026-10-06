//
//  TelemetrySchemaSource+FileEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - File events
extension TelemetrySchemaSource {
    /// File system, file metadata, memory mapping and mounting events.
    static var fileEvents: [SchemaEvent] {
        [create, rename,
         event(ES_EVENT_TYPE_NOTIFY_OPEN, "A file opened: es_event_open_t.", [
            eslogger("file", .ref("file")), eslogger("fflag", .integer),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_WRITE, "A file written: es_event_write_t.", [eslogger("target", .ref("file"))]),
         event(ES_EVENT_TYPE_NOTIFY_CLOSE, "A file closed: es_event_close_t.", [
            eslogger("target", .ref("file")), eslogger("modified", .boolean),
            eslogger("was_mapped_writable", .boolean),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_UNLINK, "A file deleted: es_event_unlink_t.", [
            eslogger("target", .ref("file")), eslogger("parent_dir", .ref("file")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_DUP, "A file descriptor duplicated: es_event_dup_t.", [
            eslogger("target", .ref("file")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_LINK, "A hard link made: es_event_link_t.", [
            eslogger("source", .ref("file")), eslogger("target_dir", .ref("file")),
            eslogger("target_filename", .string),
         ]),
         attribute(ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "An extended attribute set: es_event_setextattr_t."),
         attribute(ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "An extended attribute read: es_event_getextattr_t."),
         attribute(ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "An extended attribute deleted: es_event_deleteextattr_t."),
         event(ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "A file's extended attributes listed: es_event_listextattr_t.", [
            eslogger("target", .ref("file")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_SETMODE, "A file's mode set: es_event_setmode_t.", [
            eslogger("mode", .integer), eslogger("target", .ref("file")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_MMAP, "A file mapped into memory: es_event_mmap_t.", [
            eslogger("protection", .integer), eslogger("max_protection", .integer), eslogger("flags", .integer),
            eslogger("file_pos", .integer), eslogger("source", .ref("file")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_MPROTECT, "A memory region's protection changed: es_event_mprotect_t.", [
            eslogger("protection", .integer),
            eslogger("address", .integer, "Unsigned."),
            eslogger("size", .integer, "Unsigned."),
            addition("hex_address", .string, "`address` in hex."),
            addition("kb_size", .integer, "`size` in kilobytes."),
            addition("flags", .array(.string), "The names of the flags `protection` has: PROT_READ."),
         ]),
         mount,
        ]
    }
    
    /// An extended attribute event: its file and the attribute's name.
    ///
    /// - Parameters:
    ///   - type: The event's type.
    ///   - description: What the event is.
    /// - Returns: The event.
    private static func attribute(_ type: es_event_type_t, _ description: String) -> SchemaEvent {
        event(type, description, [eslogger("target", .ref("file")), eslogger("extattr", .string)])
    }
    
    /// Where a create or rename puts its file: an existing file, or a new path.
    ///
    /// - Parameter newPath: The new path's object.
    /// - Returns: The destination's object.
    private static func destination(_ newPath: SchemaObject) -> SchemaObject {
        SchemaObject("The destination: an existing file, or a new path, as `destination_type` says.", [
            eslogger("existing_file", .ref("file"), absent: Absence("the destination is a new path")),
            eslogger("new_path", .object(newPath), absent: Absence("the destination is an existing file")),
        ], keyCount: 0...1)
    }
    
    /// Mac Monitor's keys of a create or rename: the destination type's name, and File Quarantine.
    private static var destinationAdditions: [SchemaKey] {
        [addition("destination_type_string", .string, "The name of `destination_type`."),
         addition("is_quarantined", .integer,
                  "Whether the file was quarantined when the event was recorded: 1 if it had a "
                  + "com.apple.quarantine attribute, 0 if not, 2 if it wasn't found.")]
    }
    
    /// A file created: `es_event_create_t`.
    private static var create: SchemaEvent {
        let newPath = SchemaObject("A file not yet created: its directory, name and mode.", [
            eslogger("dir", .ref("file")), eslogger("filename", .string), eslogger("mode", .integer),
        ])
        return event(ES_EVENT_TYPE_NOTIFY_CREATE, "A file created: es_event_create_t.", [
            eslogger("destination_type", .integer),
            eslogger("destination", .object(destination(newPath))),
            eslogger("acl", .nullable(.string)),
        ] + destinationAdditions)
    }
    
    /// A file renamed: `es_event_rename_t`.
    private static var rename: SchemaEvent {
        let newPath = SchemaObject("A path that doesn't exist yet: its directory and name.", [
            eslogger("dir", .ref("file")), eslogger("filename", .string),
        ])
        return event(ES_EVENT_TYPE_NOTIFY_RENAME, "A file renamed: es_event_rename_t.", [
            eslogger("source", .ref("file")),
            eslogger("destination_type", .integer),
            eslogger("destination", .object(destination(newPath))),
            addition("destination_path", .string, "The destination's full path."),
        ] + destinationAdditions)
    }
    
    /// A file system mounted: `es_event_mount_t`.
    private static var mount: SchemaEvent {
        let integers = ["f_bsize", "f_iosize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_owner",
                        "f_type", "f_flags", "f_fssubtype", "f_flags_ext"]
        let statfs = SchemaObject("The file system's struct statfs.", integers.map { eslogger($0, .integer) } + [
            eslogger("f_fsid", .array(.integer)), eslogger("f_fstypename", .string),
            eslogger("f_mntonname", .string), eslogger("f_mntfromname", .string),
        ])
        return event(ES_EVENT_TYPE_NOTIFY_MOUNT, "A file system mounted: es_event_mount_t.", [
            eslogger("statfs", .object(statfs)),
        ] + named("disposition", "The es_mount_disposition_t: ES_MOUNT_DISPOSITION_UNKNOWN before message version 8."))
    }
}
