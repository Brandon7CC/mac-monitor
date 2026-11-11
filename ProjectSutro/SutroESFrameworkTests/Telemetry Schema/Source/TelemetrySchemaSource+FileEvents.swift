//
//  TelemetrySchemaSource+FileEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity
@testable import SutroESFramework


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
         ] + fileType(of: "target", when: ", only when `modified` is true (an unmodified close's file isn't read)")),
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
            enrichment("mode_symbolic", .string,
                       "`mode`'s permission bits as `ls -l` shows them, without the file type: rw-r--r--. Setuid and "
                       + "setgid show in the owner's and group's execute place as s, or S without execute, and the "
                       + "sticky bit in others' as t or T. Derived from `mode` when the record is written. Since "
                       + "telemetry 1.1.0."),
            enrichment("previous_mode", .nullable(.integer),
                       "The file's permission bits before the change (st_mode & 07777): Endpoint Security's stat of "
                       + "`target` is from before it. null when `target` has no stat. Derived when the record is "
                       + "written. Since telemetry 1.1.0."),
            enrichment("mode_added", .array(.values(FileModeCallout.allCases.map(\.telemetryName))),
                       "What the change added that's worth a look, in this order: executable (an execute bit, as "
                       + "chmod +x gives), setuid, setgid and world_writable (S_IWOTH). A directory gets none of the "
                       + "first three, and a sticky directory (1777, as /tmp is) not world_writable either. Without "
                       + "`previous_mode`, every bit `mode` sets counts as added. Derived when the record is "
                       + "written. Since telemetry 1.1.0."),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_MMAP, "A file mapped into memory: es_event_mmap_t.", [
            eslogger("protection", .integer), eslogger("max_protection", .integer), eslogger("flags", .integer),
            eslogger("file_pos", .integer), eslogger("source", .ref("file")),
            enrichment("protection_names", .array(.string), Self.protectionNames("protection")),
            enrichment("max_protection_names", .array(.string), Self.protectionNames("max_protection", note:
                " It's a vm_prot_t, named with PROT_* too: its low three bits are VM_PROT_READ, VM_PROT_WRITE and "
                + "VM_PROT_EXECUTE, the same bits.")),
            enrichment("flag_names", .array(.string),
                       "The names of the bits `flags` has, from sys/mman.h, in bit order, one name per bit: "
                       + "MAP_SHARED, MAP_PRIVATE (not MAP_COPY), MAP_FIXED, MAP_RENAME, MAP_NORESERVE, "
                       + "MAP_RESERVED0080, MAP_NOEXTEND, MAP_HASSEMAPHORE, MAP_NOCACHE, MAP_JIT, MAP_ANON (not "
                       + "MAP_ANONYMOUS), MAP_RESILIENT_CODESIGN, MAP_RESILIENT_MEDIA, MAP_32BIT, "
                       + "MAP_TRANSLATED_ALLOW_EXECUTE, MAP_UNIX03, MAP_TPRO. Empty for flags of 0: MAP_FILE is 0, so "
                       + "it's never named. Bits sys/mman.h doesn't name are left out; `flags` keeps them."),
         ] + fileType(of: "source")),
         event(ES_EVENT_TYPE_NOTIFY_MPROTECT, "A memory region's protection changed: es_event_mprotect_t.", [
            eslogger("protection", .integer),
            eslogger("address", .integer, "Unsigned."),
            eslogger("size", .integer, "Unsigned."),
            enrichment("hex_address", .string, "`address` in hex."),
            enrichment("kb_size", .integer, "`size` in kilobytes."),
            enrichment("flags", .array(.string),
                       "The names of the flags `protection` has, from mach/vm_prot.h, in bit order: VM_PROT_READ, "
                       + "VM_PROT_WRITE, VM_PROT_EXECUTE. VM_PROT_NONE alone for 0. Other bits are left out; "
                       + "`protection` keeps them."),
         ]),
         mount,
        ]
    }
    
    /// `file_type` and `mach_o_type`: what an event's file is, read from its first bytes at capture.
    ///
    /// - Parameters:
    ///   - key: The file's key: `source` or `target`.
    ///   - when: When the file is read, after "when it recorded it", or "" for every event.
    /// - Returns: The two keys.
    private static func fileType(of key: String, when: String = "") -> [SchemaKey] {
        [
            enrichment("file_type", .nullable(.string),
                       "What `\(key)` is by its content, never its name: the Launch Services type identifier of its "
                       + "first 4 KB, sniffed by the Mac that recorded the event when it recorded it\(when). A Mach-O "
                       + "is com.apple.mach-o-executable, -dylib, -bundle, -object or -core by its filetype, else "
                       + "com.apple.mach-o-binary (a universal binary by the slice the recording Mac runs, else its "
                       + "first; one whose slice is a static library is public.archive). A script is named by its #! "
                       + "interpreter, through /usr/bin/env too: public.zsh-script, public.python-script, "
                       + "com.apple.applescript.text for osascript (com.netscape.javascript-source with -l "
                       + "JavaScript), else public.script. Compiled AppleScript and JXA (FasdUAS, JsOsaDAS) are "
                       + "com.apple.applescript.script, and Java class files com.sun.java-class. Archives (an Apple "
                       + "Archive raw or compressed, as aa archive writes it), disk images (a UDIF trailer), ELF and "
                       + "PE binaries, property lists and PDFs have their own; other UTF-8 text without a NUL is "
                       + "public.plain-text, and anything else public.data. Or `empty` "
                       + "for a file of 0 bytes by the event's stat, `dyld_shared_cache` for a dyld shared cache (its "
                       + "first bytes are dyld_v1), and `replaced` when the path no longer names `\(key)`: its device "
                       + "or inode differ, or a symbolic link is on the path now. null when the file isn't read: not "
                       + "a regular file, dataless, on a volume that isn't local, gone, a path Endpoint Security cut "
                       + "short, or not readable by the process's effective user and group. Also null when the event "
                       + "wasn't recorded by Mac Monitor 3.1.0 or later (an eslogger trace, or one exported before "
                       + "3.1.0): the file is read only at capture, never when a trace is opened. Since telemetry "
                       + "1.1.0."),
            enrichment("mach_o_type", .nullable(.string),
                       "The mach-o/loader.h name of a Mach-O's filetype, read with `file_type`: MH_EXECUTE, MH_DYLIB, "
                       + "MH_BUNDLE, MH_OBJECT, MH_CORE, MH_DYLINKER, MH_KEXT_BUNDLE, MH_FILESET, MH_DSYM and the "
                       + "others, or its value in hex (0x1f) for one without a name. A universal binary's is that of "
                       + "the slice `file_type` names it by. null when `\(key)` isn't Mach-O, or as `file_type` is. "
                       + "Since telemetry 1.1.0."),
        ]
    }
    
    /// The description of an mmap protection's names.
    ///
    /// - Parameters:
    ///   - key: The protection's key: `protection` or `max_protection`.
    ///   - note: What else to say about the protection, after its names.
    /// - Returns: The description.
    private static func protectionNames(_ key: String, note: String = "") -> String {
        "The names of the bits `\(key)` has, from sys/mman.h, in bit order: PROT_READ, PROT_WRITE, PROT_EXEC."
            + note + " PROT_NONE alone for 0. Other bits are left out; `\(key)` keeps them."
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
    private static var destinationEnrichments: [SchemaKey] {
        [enrichment("destination_type_string", .string, "The name of `destination_type`."),
         enrichment("is_quarantined", .integer,
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
        ] + destinationEnrichments)
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
            enrichment("destination_path", .string, "The destination's full path."),
        ] + destinationEnrichments + fileType(of: "source", when: ", where it was renamed to, or from the bytes the "
            + "modified close that wrote that version of it read, as a file written under one name and renamed into "
            + "place is"))
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
