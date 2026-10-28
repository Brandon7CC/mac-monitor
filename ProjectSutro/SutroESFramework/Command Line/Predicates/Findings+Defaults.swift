//
//  Findings+Defaults.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Defaults
public extension Finding {
    /// The findings Mac Monitor ships, each with an identity of its own, so Restore Defaults puts back the same ones.
    static let defaults: [Finding] = [
        Finding(id: uuid(1), name: "Reflective loading",
                explanation: "Wrote or mapped the image NSCreateObjectFileImageFromMemory makes of a Mach-O it loads "
                    + "from memory: reflective code loading (T1620).",
                symbol: "memorychip", color: .red,
                predicate: type("CREATE", "WRITE", "MMAP")
                    + #" AND target_path CONTAINS "/NSCreateObjectFileImageFromMemory-""#,
                correlation: true, groups: false),
        Finding(id: uuid(2), name: "Not quarantined",
                explanation: "Written without the quarantine attribute by a process whose files macOS quarantines, or "
                    + "by ArchiveService outside its temporary folder. Gatekeeper won't check it when it's opened.",
                symbol: "exclamationmark.shield", color: .orange,
                predicate: "(" + type("CREATE", "RENAME") + #" AND process.file_quarantine_type != "DISABLED" "#
                    + "AND (event.create.is_quarantined == 0 OR event.rename.is_quarantined == 0)) OR ("
                    + type("CREATE") + #" AND process.executable.name == "ArchiveService" "#
                    + #"AND NOT target_path BEGINSWITH "/private/var/folders/" AND event.create.is_quarantined == 0)"#,
                correlation: true, groups: false),
        Finding(id: uuid(3), name: "Quarantine removed",
                explanation: "Deleted com.apple.quarantine, so Gatekeeper won't check the file when it's opened.",
                symbol: "xmark.shield", color: .red,
                predicate: type("DELETEEXTATTR") + #" AND event.deleteextattr.extattr ENDSWITH "apple.quarantine""#,
                correlation: true, groups: false),
        Finding(id: uuid(4), name: "Background item added",
                explanation: "Added a background item, which runs again at login.",
                symbol: "gearshape.2", color: .green, predicate: type("BTM_LAUNCH_ITEM_ADD"),
                correlation: true, groups: false),
        Finding(id: uuid(5), name: "XProtect detection",
                explanation: "XProtect detected or remediated malware.",
                symbol: "xmark.octagon", color: .red, predicate: type("XP_MALWARE_DETECTED", "XP_MALWARE_REMEDIATED"),
                correlation: true, groups: false),
        Finding(id: uuid(6), name: "AppleScript loaded",
                explanation: "Mapped an Open Scripting Architecture component, as a process running AppleScript does.",
                symbol: "applescript", color: .purple,
                predicate: type("MMAP") + #" AND (target_path CONTAINS "AppleScript.component" "#
                    + #"OR target_path CONTAINS "JavaScript.component" OR target_path CONTAINS ".osax")"#,
                correlation: true, groups: false),
        Finding(id: uuid(7), name: "Keychain opened",
                explanation: "Opened a keychain, which holds passwords and keys.",
                symbol: "key", color: .blue, predicate: type("OPEN") + #" AND target_path CONTAINS "/Keychains/""#,
                correlation: true, groups: false),
        Finding(id: uuid(8), name: "Login",
                explanation: "A login, by the login window, login(1), or SSH.",
                symbol: "person.badge.key", color: .blue,
                predicate: type("LOGIN_LOGIN", "LW_SESSION_LOGIN", "OPENSSH_LOGIN"),
                correlation: true, groups: false),
        Finding(id: uuid(9), name: "New executable",
                explanation: "Its executable was created less than five minutes before it ran, as a dropper's payload "
                    + "is.",
                symbol: "clock.badge.exclamationmark", color: .orange,
                predicate: type("EXEC") + " AND event.exec.executable_age_ms >= 0 "
                    + "AND event.exec.executable_age_ms < 300000",
                correlation: false, groups: true, tables: true),
        Finding(id: uuid(10), name: "Adhoc or unsigned",
                explanation: "Ran code that isn't signed by a known developer: adhoc, as a freshly compiled or "
                    + "modified binary is, or not at all.",
                symbol: "xmark.seal", color: .orange,
                predicate: type("EXEC") + #" AND (event.exec.target.codesigning_type IN {"ADHOC", "UNSIGNED"} "#
                    + "OR event.exec.target.is_adhoc_signed == YES OR event.exec.target.signing_id == nil "
                    + #"OR event.exec.target.signing_id IN {"", "Unknown"})"#,
                correlation: false, groups: true),
        Finding(id: uuid(11), name: "Ran a script",
                explanation: "An interpreter ran a script Mac Monitor read. That exec's Script tab shows its content.",
                symbol: "scroll.fill", color: .purple,
                predicate: type("EXEC") + #" AND event.exec.script_content != nil AND event.exec.script_content != """#,
                correlation: false, groups: true, tables: true),
        Finding(id: uuid(12), name: "osascript",
                explanation: "osascript ran AppleScript or JXA, which stealers use for fake password prompts and to "
                    + "drive other apps.",
                symbol: "applescript", color: .indigo,
                predicate: type("EXEC") + #" AND event.exec.target.executable.name == "osascript""#,
                correlation: false, groups: true),
        Finding(id: uuid(13), name: "Download tool",
                explanation: "A command line download tool ran, as a dropper does to fetch its payload.",
                symbol: "arrow.down.circle", color: .blue,
                predicate: type("EXEC") + " AND event.exec.target.executable.name "
                    + #"IN {"curl", "wget", "nscurl", "ftp", "tftp", "scp", "sftp"}"#,
                correlation: false, groups: true),
        Finding(id: uuid(14), name: "Non-Apple as root",
                explanation: "Ran as root without Apple's signature.",
                symbol: "bolt.shield", color: .red,
                predicate: type("EXEC") + #" AND event.exec.target.euid == 0 "#
                    + #"AND event.exec.target.codesigning_type != "PLATFORM""#,
                correlation: false, groups: true),
    ]
}


// MARK: - Built-in marks
public extension Finding {
    /// The marks an event type's label draws before its name, in the Unified table and Event Facts, as its hard-coded
    /// label drew them. A mark's explanation is its help. In it, `{age}` and `{script}` stand for the exec's
    /// executable age and its script's path. A mark with a default's identity is that default's twin. Their order is
    /// the marks' order.
    static let labelMarks: [Finding] = execMarks + fileMarks + systemMarks

    /// The marks the Process Execution table draws before an exec's findings and process name.
    static let nameMarks: [Finding] = [
        mark(15, "Root user", "Process is running as the root user",
             symbol: "person.crop.circle.badge.exclamationmark.fill", rendering: .multicolor,
             predicate: type("EXEC") + " AND event.exec.target.ruid == 0"),
        mark(16, "Elevated to root", "Process elevated to root!", symbol: "key.radiowaves.forward.fill",
             rendering: .multicolor,
             predicate: type("EXEC") + " AND event.exec.target.euid == 0 AND event.exec.target.ruid != 0"),
        dyldInsertion,
        mark(40, "File Quarantine-aware process", "Process is File Quarantine-aware.", symbol: "lock.icloud",
             rendering: .multicolor, predicate: quarantineAware),
    ]

    /// Every built-in mark, once. They aren't listed or edited anywhere.
    static let builtInMarks: [Finding] = labelMarks + nameMarks.filter { !labelMarks.contains($0) }

    /// The findings marking an event in the tables that are drawn beside the built-in marks it matches. A finding that
    /// is a matched mark's twin, with the mark's symbol, is drawn once, as the mark.
    ///
    /// - Parameters:
    ///   - findings: The findings marking the tables that the event matches.
    ///   - marks: The built-in marks the event matches, drawn beside them.
    /// - Returns: The findings to draw.
    static func findings(_ findings: [Finding], besides marks: [Finding]) -> [Finding] {
        findings.filter { finding in !marks.contains { $0.id == finding.id && $0.symbol == finding.symbol } }
    }
}


// MARK: - Execs
private extension Finding {
    /// The marks an exec's label draws.
    static let execMarks: [Finding] = [
        twin(9, "Its executable was {age} old at exec.", rendering: .palette, palette: [.orange, .primary]),
        twin(11, "Ran {script}. Event Facts' Script tab shows its content."),
        dyldInsertion,
        mark(19, "File Quarantine-aware", "Target is File Quarantine-aware.", symbol: "lock.icloud",
             rendering: .multicolor, predicate: quarantineAware),
    ]

    /// The mark for a dyld injection, which the label and the process name both draw.
    static let dyldInsertion = mark(17, "DYLD_INSERT_LIBRARIES", "Dyld injection attempt.", symbol: "bookmark.slash",
                                    color: .red, rendering: .palette, palette: [.red],
                                    predicate: type("EXEC") + #" AND ANY event.exec.env CONTAINS[c] "#
                                        + #""DYLD_INSERT_LIBRARIES""#)

    /// An exec of a process that's File Quarantine-aware.
    static let quarantineAware = type("EXEC") + #" AND event.exec.target.file_quarantine_type != "DISABLED""#
}


// MARK: - Files
private extension Finding {
    /// The marks a file event's label draws.
    static let fileMarks: [Finding] = [
        warning(34, "Reflective loading image",
                "NSCreateObjectFileImageFromMemory's image of a Mach-O loaded from memory: reflective code loading "
                    + "(T1620)", color: .red, type("CREATE", "MMAP") + " AND " + reflective),
        warning(35, "Unquarantined file created", "Unquarantined file created",
                type("CREATE") + " AND NOT " + reflective + #" AND (process.file_quarantine_type != "DISABLED" "#
                    + #"OR (process.executable.name == "ArchiveService" "#
                    + #"AND NOT target_path BEGINSWITH "/private/var/folders/")) "#
                    + "AND event.create.is_quarantined == 0"),
        mark(20, "Quarantined file", "File is quarantined", symbol: "lock.shield",
             predicate: type("CREATE") + " AND NOT " + reflective + " AND event.create.is_quarantined == 1"),
        warning(36, "OSA component mapped", "This file is an OSA (Open Scripting Architecture) component",
                type("MMAP") + " AND NOT " + reflective + #" AND (target_path CONTAINS "AppleScript.component" "#
                    + #"OR target_path CONTAINS "JavaScript.component" OR target_path CONTAINS ".osax")"#),
        mark(22, "Quarantined file renamed", "File is quarantined", symbol: "lock.shield", rendering: .palette,
             palette: [.primary], predicate: type("RENAME") + " AND event.rename.is_quarantined == 1"),
        mark(21, "Unquarantined app bundle", "Unquarantined application bundle", symbol: "hand.raised.app",
             color: .red, rendering: .palette, palette: [.red], predicate: type("RENAME") + " AND " + unquarantinedApp),
        mark(24, "BTM database modified", "Service management database modified.",
             symbol: "exclamationmark.triangle.fill", color: .yellow, rendering: .palette, palette: [.yellow],
             predicate: type("RENAME") + #" AND target_path CONTAINS "com.apple.backgroundtaskmanagement" "#
                + "AND NOT event.rename.is_quarantined == 1 AND NOT (" + unquarantinedApp + ")"),
        warning(37, "Quarantine attribute deleted", "Quarantine extended attribute deleted",
                type("DELETEEXTATTR") + #" AND event.deleteextattr.extattr ENDSWITH "apple.quarantine""#),
        warning(23, "Login Item written", "A Login Item was potentially added",
                type("WRITE") + #" AND target_path CONTAINS "backgroundtaskmanagementd""#),
    ]

    /// A file the image `NSCreateObjectFileImageFromMemory` writes to load a Mach-O from memory.
    static let reflective = #"target_path CONTAINS "/NSCreateObjectFileImageFromMemory-""#
    /// An app bundle renamed into place without the quarantine attribute.
    static let unquarantinedApp = #"event.rename.is_quarantined == 0 AND target_path ENDSWITH ".app""#
}


// MARK: - System
private extension Finding {
    /// The marks the rest of the system's labels draw.
    static let systemMarks: [Finding] = [
        warning(38, "Background item added", "These events indicate a background task was added",
                type("BTM_LAUNCH_ITEM_ADD")),
        warning(25, "Background item removed", "These events indicate a background task was removed",
                type("BTM_LAUNCH_ITEM_REMOVE")),
        warning(39, "XProtect malware", "", color: .purple, type("XP_MALWARE_DETECTED", "XP_MALWARE_REMEDIATED")),
        warning(26, "HID device opened", "Human Interface Device (HID) attached!",
                type("IOKIT_OPEN") + #" AND event.iokit_open.user_client_class CONTAINS "IOHIDLibUserClient""#),
        warning(27, "Remote thread created", "Remote thread created!", type("REMOTE_THREAD_CREATE")),
        warning(28, "Code signature invalidated", "This process has its code signature invalidated!",
                type("CS_INVALIDATED")),
        warning(29, "Process traced", "Process trace occuring", type("TRACE")),
        warning(30, "Task port retrieved", "Retrieving task control port!", type("GET_TASK")),
        mark(31, "Non-zero exit", "Non-zero exit code", symbol: "info.square", rendering: .palette,
             predicate: type("EXIT") + " AND event.exit.stat != 0"),
    ]
}


// MARK: - Building
private extension Finding {
    /// - Parameter number: A default's or a mark's number.
    /// - Returns: Its identity, the same on every Mac.
    static func uuid(_ number: Int) -> UUID {
        UUID(uuidString: String(format: "6D4D0F1D-0000-4000-8000-%012X", number))!
    }

    /// - Parameter types: Event types, without `ES_EVENT_TYPE_NOTIFY_`.
    /// - Returns: The comparison an event of one of them passes, as in `es_event_type == "ES_EVENT_TYPE_NOTIFY_EXIT"`.
    static func type(_ types: String...) -> String {
        let names = types.map { #""ES_EVENT_TYPE_NOTIFY_\#($0)""# }
        return names.count == 1 ? "es_event_type == \(names[0])"
            : "es_event_type IN {\(names.joined(separator: ", "))}"
    }

    /// A built-in mark. It marks the tables only.
    ///
    /// - Parameters:
    ///   - number: Its number.
    ///   - name: What it's called.
    ///   - explanation: Its help. An empty one shows none.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - rendering: How its symbol is drawn.
    ///   - palette: The colors of its symbol's layers, for a palette.
    ///   - predicate: The predicate an event matches.
    /// - Returns: The mark.
    static func mark(_ number: Int, _ name: String, _ explanation: String, symbol: String, color: Color = .primary,
                     rendering: Rendering = .monochrome, palette: [Color] = [], predicate: String) -> Finding {
        Finding(id: uuid(number), name: name, explanation: explanation, symbol: symbol, color: color,
                rendering: rendering, palette: palette, predicate: predicate,
                correlation: false, groups: false, tables: true)
    }

    /// A built-in mark drawn as the warning triangle, black on a color.
    ///
    /// - Parameters:
    ///   - number: Its number.
    ///   - name: What it's called.
    ///   - explanation: Its help. An empty one shows none.
    ///   - color: The triangle's color.
    ///   - predicate: The predicate an event matches.
    /// - Returns: The mark.
    static func warning(_ number: Int, _ name: String, _ explanation: String, color: Color = .yellow,
                        _ predicate: String) -> Finding {
        mark(number, name, explanation, symbol: "exclamationmark.triangle.fill", color: color,
             rendering: .palette, palette: [.black, color], predicate: predicate)
    }

    /// A default's twin. It's a built-in mark with the default's identity, name, predicate and symbol.
    ///
    /// - Parameters:
    ///   - number: The default's number.
    ///   - explanation: The mark's help.
    ///   - rendering: How the mark's symbol is drawn.
    ///   - palette: The colors of the mark's layers, for a palette.
    /// - Returns: The mark.
    static func twin(_ number: Int, _ explanation: String, rendering: Rendering = .monochrome,
                     palette: [Color] = []) -> Finding {
        let finding = defaults.first { $0.id == uuid(number) }!
        return mark(number, finding.name, explanation, symbol: finding.symbol, color: finding.color,
                    rendering: rendering, palette: palette, predicate: finding.predicate)
    }
}
