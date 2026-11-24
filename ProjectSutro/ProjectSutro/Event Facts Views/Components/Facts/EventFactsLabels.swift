//
//  EventFactsLabels.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Event Facts
/// An event's time in Event Facts: this Mac's local time, with eslogger's UTC `time`, exactly as recorded, on hover.
struct EventTimeView: View {
    /// The event.
    let message: ESMessage
    
    /// Local time to the millisecond, with the time zone: "2026-10-02 05:15:49.123 PDT".
    private static let localTime: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS zzz"
        return formatter
    }()
    
    /// The local time in a box, or eslogger's time if the event has no `Date`.
    var body: some View {
        GroupBox {
            Text("`\(message.message_darwin_time.map(Self.localTime.string(from:)) ?? message.time ?? "Unknown")`")
        }
        .help(message.time ?? "")
    }
}


/// A file's path in Event Facts: its name with whether the file exists, the path, and Show in Finder while it does.
/// The check is made on this Mac, which for a trace may not be the Mac the event happened on, so for a trace its
/// help says so.
struct FilePathFact: View {
    /// The fact's name, without a colon.
    var name = "File path"
    /// The file's path.
    let path: String

    /// The name, with a check mark if the file exists and a cross if it doesn't, then the path.
    var body: some View {
        let exists = FileManager.default.fileExists(atPath: path)
        let trace = CoreDataController.shared.isShowingTrace
        FactRow {
            Fact(name, path, systemImage: exists ? "checkmark.circle" : "xmark.circle")
                .help(exists ? (trace ? "This file exists on this Mac." : "This file exists.")
                      : (trace ? "This file isn't on this Mac." : "This file no longer exists."))
            ShowInFinderButton(path: path)
        }
    }
}
