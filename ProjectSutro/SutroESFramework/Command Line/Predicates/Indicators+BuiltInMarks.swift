//
//  Indicators+BuiltInMarks.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Built-in marks
public extension Indicator {
    /// The marks an event type's label draws before its name, in the Unified table and Event Facts, as its hard-coded
    /// label drew them. A mark's description is its help. In it, `{age}` and `{script}` stand for the exec's
    /// executable age and its script's path. A mark with a default's identity is that default's twin. Their order is
    /// the marks' order.
    static let labelMarks: [Indicator] = execMarks + fileMarks + systemMarks

    /// The marks the Process Execution table draws before an exec's indicators and process name.
    static let nameMarks: [Indicator] = [
        mark(15, "Root user", "Process is running as the root user",
             symbol: "person.crop.circle.badge.exclamationmark.fill",
             predicate: type("EXEC") + " AND event.exec.target.ruid == 0"),
        dyldInsertion,
        mark(40, "File Quarantine-aware process", "Process is File Quarantine-aware.", symbol: "lock.icloud",
             predicate: quarantineAware),
    ]

    /// Every built-in mark, once. They aren't listed or edited anywhere.
    static let builtInMarks: [Indicator] = labelMarks + nameMarks.filter { !labelMarks.contains($0) }

    /// The indicators marking an event in the tables that are drawn beside the built-in marks it matches. An indicator
    /// that is a matched mark's twin, with the mark's symbol, is drawn once, as the mark.
    ///
    /// - Parameters:
    ///   - indicators: The indicators marking the tables that the event matches.
    ///   - marks: The built-in marks the event matches, drawn beside them.
    /// - Returns: The indicators to draw.
    static func drawn(_ indicators: [Indicator], besides marks: [Indicator]) -> [Indicator] {
        indicators.filter { indicator in !marks.contains { $0.id == indicator.id && $0.symbol == indicator.symbol } }
    }
}


// MARK: - Execs
private extension Indicator {
    /// The marks an exec's label draws.
    static let execMarks: [Indicator] = [
        twin(9, "Its executable was {age} old at exec."),
        twin(11, "Ran {script}. Event Facts' Script tab shows its content."),
        dyldInsertion,
        mark(19, "File Quarantine-aware", "Target is File Quarantine-aware.", symbol: "lock.icloud",
             predicate: quarantineAware),
    ]

    /// The mark for an inserted dylib, which the label and the process name both draw: the Dylib inserted
    /// indicator's twin, so the two draw once and Settings changes both.
    static let dyldInsertion = twin(50, "Dyld injection attempt: DYLD_INSERT_LIBRARIES is set.")

    /// An exec of a process that's File Quarantine-aware.
    static let quarantineAware = type("EXEC") + #" AND event.exec.target.file_quarantine_type != "DISABLED""#
}


// MARK: - Files
public extension Indicator {
    /// The identity of the Unquarantined file from a File Quarantine-aware app default, which Event Facts reads to
    /// explain an unquarantined file.
    static let unquarantinedFileID = uuid(35)
}

private extension Indicator {
    /// The marks a file event's label draws. Those for a rename onto Background Task Management's database (24) and
    /// for a file a File Quarantine-aware app creates without the quarantine attribute (35) became the BTM database
    /// modified and Unquarantined file from a File Quarantine-aware app defaults in 3.1.0, which color the event's
    /// label as the label did.
    static let fileMarks: [Indicator] = [
        mark(20, "Quarantined file", "File is quarantined", symbol: "lock.shield",
             predicate: type("CREATE") + " AND NOT " + reflective + " AND event.create.is_quarantined == 1"),
        mark(22, "Quarantined file renamed", "File is quarantined", symbol: "lock.shield",
             predicate: type("RENAME") + " AND event.rename.is_quarantined == 1"),
        mark(21, "Unquarantined app bundle", "Unquarantined application bundle", symbol: "hand.raised.app",
             color: .red, predicate: type("RENAME") + " AND " + unquarantinedApp),
        warning(23, "Login Item written", "A Login Item was potentially added",
                type("WRITE") + #" AND target_path CONTAINS "backgroundtaskmanagementd""#),
    ]

    /// A file the image `NSCreateObjectFileImageFromMemory` writes to load a Mach-O from memory.
    static let reflective = #"target_path CONTAINS "/NSCreateObjectFileImageFromMemory-""#
    /// An app bundle renamed into place without the quarantine attribute.
    static let unquarantinedApp = #"event.rename.is_quarantined == 0 AND target_path ENDSWITH ".app""#
}


// MARK: - System
private extension Indicator {
    /// The marks the rest of the system's labels draw. Those for what's worth a look, a background item, XProtect, an
    /// input device, a remote thread, an invalidated signature, a trace or a task port, became defaults in 3.1.0, which
    /// color the event's label as these marks and the label did (``Indicator/TableMarks/label``).
    static let systemMarks: [Indicator] = [
        mark(31, "Non-zero exit", "Non-zero exit code", symbol: "info.square",
             predicate: type("EXIT") + " AND event.exit.stat != 0"),
    ]
}
