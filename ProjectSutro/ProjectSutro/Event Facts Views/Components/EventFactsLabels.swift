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


/// The title of a file path in Event Facts, with whether the file exists. The check is made on this Mac, which for a trace
/// may not be the Mac the event happened on, so for a trace the label says so.
struct FileExistsLabel: View {
    /// The label's title (Markdown).
    let title: LocalizedStringKey
    /// The file's path.
    let path: String
    
    /// The title, with a check mark if the file exists and a cross if it doesn't, and, for a trace, "on this Mac".
    var body: some View {
        let exists = FileManager.default.fileExists(atPath: path)
        let trace = CoreDataController.shared.isShowingTrace
        HStack(spacing: 4) {
            Label(title, systemImage: exists ? "checkmark.circle" : "xmark.circle")
                .labelStyle(.titleAndIcon)
            if trace {
                Text(exists ? "on this Mac" : "not on this Mac")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .help(exists ? (trace ? "This file exists on this Mac." : "This file exists.")
              : (trace ? "This file isn't on this Mac." : "This file no longer exists."))
    }
}
