//
//  MuteTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Mute table
/// The saved mute set as `macmonitor mute list` shows it: one mute a line, with its type and events by the names
/// `macmonitor mute add` takes, and every path escaped for a terminal.
///
/// ```
/// TYPE            EVENTS        PATH
/// literal         every event   /usr/libexec/logd
/// target-prefix   mmap          /Library/Caches/
/// ```
public enum MuteTable {
    /// The table.
    ///
    /// - Parameter mutes: The saved set's entries, in canonical order.
    /// - Returns: The text, ending in a newline.
    public static func text(_ mutes: [MuteFile.Entry]) -> String {
        guard !mutes.isEmpty else { return "The saved mute set is empty.\n" }
        let rows = [("TYPE", "EVENTS", "PATH")]
            + mutes.map { (type($0.type), events($0.events), TerminalSafeText.text($0.path)) }
        let typeWidth = rows.map(\.0.count).max() ?? 0, eventsWidth = rows.map(\.1.count).max() ?? 0
        return rows.map { row in
            pad(row.0, typeWidth) + "   " + pad(row.1, eventsWidth) + "   " + row.2
        }.joined(separator: "\n") + "\n"
    }
    
    /// An entry in a sentence, such as "/usr/bin/yes (literal, every event)".
    ///
    /// - Parameter entry: The entry.
    /// - Returns: The words.
    public static func describe(_ entry: MuteFile.Entry) -> String {
        "\(TerminalSafeText.text(entry.path)) (\(type(entry.type)), \(events(entry.events)))"
    }
    
    /// A mute type by the short name `--type` takes.
    ///
    /// - Parameter name: The `ES_MUTE_PATH_TYPE_*` name.
    /// - Returns: Such as "target-prefix", or the name as it is if it isn't one of the four.
    static func type(_ name: String) -> String {
        CommandLineParser.muteTypes.first { getMuteCaseString(muteType: $0.value) == name }?.key ?? name
    }
    
    /// Events by their short names.
    ///
    /// - Parameter names: `ES_EVENT_TYPE_*` names.
    /// - Returns: Such as "create,rename", or "every event" for none.
    static func events(_ names: [String]) -> String {
        names.isEmpty ? "every event" : names.map(CommandLineEvents.shortName).joined(separator: ",")
    }
    
    /// Text padded with spaces to a width.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - width: The width.
    /// - Returns: The padded text.
    private static func pad(_ text: String, _ width: Int) -> String {
        text + String(repeating: " ", count: max(0, width - text.count))
    }
}
