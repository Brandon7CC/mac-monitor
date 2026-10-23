//
//  GroupSummary.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Summary
/// The execs in an event's process group or session, as the Groups tab shows them: a row each, how they're signed,
/// and the findings worth a look. Made on the main thread, the view context's queue.
struct GroupSummary {
    /// Which group.
    enum Scope: String, CaseIterable, Identifiable {
        case process = "Process group", session = "Session"
        var id: Self { self }

        /// What the group is.
        var explanation: String {
            switch self {
            case .process:
                return "Processes that share this one's process group ID: started together as one job, such as a "
                    + "shell pipeline."
            case .session:
                return "Processes that share this one's session ID: everything started from the same login, Terminal "
                    + "window, or launchd session."
            }
        }
    }

    /// How a process is signed.
    enum Signing: String, CaseIterable {
        case apple = "Apple", appStore = "App Store", developerID = "Developer ID", adhoc = "Ad hoc"
        case unsigned = "Unsigned", unknown = "Unknown"

        /// - Parameter type: A process's ``CodeSigningType``, as stored.
        init(_ type: String) {
            switch CodeSigningType(rawValue: type) {
            case .platform: self = .apple
            case .appStore: self = .appStore
            case .developerId: self = .developerID
            case .adhoc: self = .adhoc
            case .unsigned: self = .unsigned
            case .unknown, nil: self = .unknown
            }
        }

        var color: Color {
            switch self {
            case .apple: return .blue
            case .appStore: return .teal
            case .developerID: return .green
            case .adhoc: return .orange
            case .unsigned: return .red
            case .unknown: return .gray
            }
        }

        var symbol: String {
            switch self {
            case .apple, .appStore, .developerID: return "checkmark.seal"
            case .adhoc, .unsigned: return "xmark.seal"
            case .unknown: return "questionmark.diamond"
            }
        }
    }

    /// One exec.
    struct Row: Identifiable {
        let message: ESMessage
        let name: String
        let path: String
        let commandLine: String
        /// Its signing ID, or its team's.
        let signer: String
        let signing: Signing
        let user: String
        let time: String
        /// Is it the event Event Facts shows?
        let isCurrent: Bool
        /// The first finding it's part of.
        let finding: GroupFinding?

        var id: NSManagedObjectID { message.objectID }

        /// Does the row mention some text, case-insensitively?
        ///
        /// - Parameter query: The text, lowercased.
        /// - Returns: `true` if its name, path, command line or signer contains it.
        func mentions(_ query: String) -> Bool {
            [name, path, commandLine, signer].contains { $0.lowercased().contains(query) }
        }
    }

    let scope: Scope
    /// The group's process group or session ID.
    let identifier: Int
    /// Oldest first.
    let rows: [Row]
    /// Each way of signing with its number of execs, most first.
    let signings: [(signing: Signing, count: Int)]
    /// Each finding with its execs, in ``GroupFinding`` order.
    let findings: [(finding: GroupFinding, rows: [Row])]
    /// Seconds from the first exec to the last.
    let span: Double

    /// - Parameters:
    ///   - scope: Which group.
    ///   - execs: Its exec events, newest first.
    ///   - current: The event Event Facts shows.
    init(scope: Scope, execs: [ESMessage], current: ESMessage) {
        self.scope = scope
        let process = current.event.exec?.target ?? current.process
        identifier = Int(scope == .process ? process.group_id : process.session_id)
        rows = execs.reversed().compactMap { message in
            guard let exec = message.event.exec else { return nil }
            let target = exec.target
            return Row(message: message, name: target.executable?.name ?? "", path: target.executable?.path ?? "",
                       commandLine: exec.command_line ?? "", signer: target.signing_id ?? target.team_id ?? "",
                       signing: Signing(target.codesigning_type), user: target.euid_human ?? "\(target.euid)",
                       time: eventTimeStamp(for: message), isCurrent: message.objectID == current.objectID,
                       finding: GroupFinding.allCases.first { $0.matches(exec) })
        }
        var counts: [Signing: Int] = [:]
        rows.forEach { counts[$0.signing, default: 0] += 1 }
        signings = Signing.allCases.compactMap { signing in counts[signing].map { (signing, $0) } }
            .sorted { $0.count > $1.count }
        let rows = rows
        findings = GroupFinding.allCases.compactMap { finding in
            let matching = rows.filter { $0.message.event.exec.map(finding.matches) ?? false }
            return matching.isEmpty ? nil : (finding, matching)
        }
        let times = rows.compactMap { $0.message.message_darwin_time }
        span = times.max().map { last in times.min().map { last.timeIntervalSince($0) } ?? 0 } ?? 0
    }

    /// - Parameter seconds: A span of time.
    /// - Returns: Such as "0.42 s", "12 s", "4 min" or "3 h 20 min".
    static func duration(_ seconds: Double) -> String {
        switch seconds {
        case ..<1: return String(format: "%.2f s", seconds)
        case ..<60: return "\(Int(seconds)) s"
        case ..<3600: return "\(Int(seconds) / 60) min"
        default: return "\(Int(seconds) / 3600) h \(Int(seconds) % 3600 / 60) min"
        }
    }
}


// MARK: - Findings
/// What's worth a look among a group's execs, each a card above them.
enum GroupFinding: String, CaseIterable, Identifiable {
    case newExecutable, unsignedCode, script, appleScript, download, nonAppleRoot

    var id: Self { self }

    /// Command line tools that download files.
    private static let downloaders: Set<String> = ["curl", "wget", "nscurl", "ftp", "tftp", "scp", "sftp"]

    /// Is an exec part of this finding?
    ///
    /// - Parameter exec: The exec.
    /// - Returns: `true` if it is.
    func matches(_ exec: ESProcessExecEvent) -> Bool {
        let target = exec.target
        switch self {
        case .newExecutable:
            return exec.isNewExecutable
        case .unsignedCode:
            return [.adhoc, .unsigned].contains(GroupSummary.Signing(target.codesigning_type))
        case .script:
            return !(exec.script_content ?? "").isEmpty
        case .appleScript:
            return target.executable?.name == "osascript"
        case .download:
            return Self.downloaders.contains(target.executable?.name ?? "")
        case .nonAppleRoot:
            return target.euid == 0 && GroupSummary.Signing(target.codesigning_type) != .apple
        }
    }

    /// The card's title.
    ///
    /// - Parameter count: How many execs are part of it.
    /// - Returns: The title, such as "2 ad hoc or unsigned".
    func title(_ count: Int) -> String {
        switch self {
        case .newExecutable: return count == 1 ? "New executable" : "\(count) new executables"
        case .unsignedCode: return "\(count) ad hoc or unsigned"
        case .script: return count == 1 ? "Ran a script" : "Ran \(count) scripts"
        case .appleScript: return count == 1 ? "AppleScript" : "AppleScript ×\(count)"
        case .download: return count == 1 ? "Download tool" : "\(count) download tools"
        case .nonAppleRoot: return "\(count) non-Apple as root"
        }
    }

    /// Why it's worth a look.
    var explanation: String {
        switch self {
        case .newExecutable:
            return "Its executable was created less than five minutes before it ran, as a dropper's payload is."
        case .unsignedCode:
            return "Ran code that isn't signed by a known developer: ad hoc, as a freshly compiled or modified binary "
                + "is, or not at all."
        case .script:
            return "An interpreter ran a script Mac Monitor read. That exec's Script tab shows its content."
        case .appleScript:
            return "osascript ran AppleScript or JXA, which stealers use for fake password prompts and to drive other "
                + "apps."
        case .download:
            return "A command line download tool ran, as a dropper does to fetch its payload."
        case .nonAppleRoot:
            return "Ran as root without Apple's signature."
        }
    }

    var symbol: String {
        switch self {
        case .newExecutable: return "clock.badge.exclamationmark"
        case .unsignedCode: return "xmark.seal"
        case .script: return "scroll.fill"
        case .appleScript: return "applescript"
        case .download: return "arrow.down.circle"
        case .nonAppleRoot: return "bolt.shield"
        }
    }

    var tint: Color {
        switch self {
        case .newExecutable: return .pink
        case .unsignedCode: return .orange
        case .script: return .purple
        case .appleScript: return .indigo
        case .download: return .blue
        case .nonAppleRoot: return .red
        }
    }
}
