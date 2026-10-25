//
//  SettingsComponents.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/22/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Panes
/// Settings' panes, as the sidebar lists them.
enum SettingsPane: String, CaseIterable, Identifiable {
    case securityExtension, subscriptions, pathMuting, findings, commandLine, telemetrySchema, general, eventTables
    case systemDetails

    /// The sidebar's groups under the Security Extension card, in order.
    static let groups: [[SettingsPane]] = [[.general], [.subscriptions, .pathMuting], [.findings],
                                           [.commandLine, .telemetrySchema], [.eventTables, .systemDetails]]

    var id: String { rawValue }

    /// The pane's name.
    var title: String {
        switch self {
        case .securityExtension: return "Security Extension"
        case .subscriptions: return "Subscriptions"
        case .pathMuting: return "Path Muting"
        case .findings: return "Findings"
        case .commandLine: return "Command Line"
        case .telemetrySchema: return "Telemetry Schema"
        case .general: return "General"
        case .eventTables: return "Context Menus"
        case .systemDetails: return "System Details"
        }
    }

    /// What the pane is for, in a sentence, under its header.
    var summary: String {
        switch self {
        case .securityExtension:
            return "The part of Mac Monitor that runs as root and talks to Endpoint Security. It needs to be allowed, "
                + "and it needs Full Disk Access."
        case .subscriptions: return "The Endpoint Security events Mac Monitor records."
        case .pathMuting:
            return "Paths whose events Mac Monitor never captures. Mac Monitor and macmonitor share one saved set."
        case .findings:
            return "What Event Facts points out among an exec's correlated events and a group's execs, and what "
                + "marks events in the tables: a predicate each."
        case .commandLine:
            return "Stream events to a terminal or a pipe with sudo macmonitor, while Mac Monitor keeps recording."
        case .telemetrySchema:
            return "The shape of every record Mac Monitor exports and macmonitor writes: eslogger's JSON plus Mac "
                + "Monitor's enrichments."
        case .general: return "Updates, warnings, and how Event Facts draws the process tree."
        case .eventTables:
            return "What right-clicking an event offers: filter by it, mute it, or unsubscribe from its type."
        case .systemDetails:
            return "This Mac, System Integrity Protection, and the Sensor ID Mac Monitor records with every event."
        }
    }

    /// The pane's SF Symbol.
    var symbol: String {
        switch self {
        case .securityExtension: return "checkmark.shield.fill"
        case .subscriptions: return "bolt.fill"
        case .pathMuting: return "speaker.slash.fill"
        case .findings: return "sparkle.magnifyingglass"
        case .commandLine: return "terminal.fill"
        case .telemetrySchema: return "curlybraces"
        case .general: return "gearshape.fill"
        case .eventTables: return "tablecells.fill"
        case .systemDetails: return "cpu"
        }
    }

    /// The pane's tile color.
    var tint: Color {
        switch self {
        case .securityExtension: return Color(red: 0.2, green: 0.29, blue: 0.37)
        case .subscriptions: return .blue
        case .pathMuting, .general: return .gray
        case .commandLine: return Color(white: 0.22)
        case .telemetrySchema: return .purple
        case .findings: return .orange
        case .eventTables: return .green
        case .systemDetails: return Color(white: 0.4)
        }
    }

    /// Words the sidebar's search finds the pane by, beside its name.
    private var keywords: [String] {
        switch self {
        case .securityExtension: return ["full disk access", "fda", "install", "uninstall", "requirements"]
        case .subscriptions: return ["events", "exec", "fork", "subscribe"]
        case .pathMuting: return ["mute", "unmute", "path", "import", "export"]
        case .findings: return ["detections", "correlation", "groups", "predicate", "reflective", "applescript", "script", "marks"]
        case .commandLine: return ["macmonitor", "terminal", "cli", "sudo"]
        case .telemetrySchema: return ["schema", "json", "validate", "trace", "export"]
        case .general: return ["update", "release notes", "version", "quit", "clear", "dark", "process tree"]
        case .eventTables: return ["event tables", "right click", "filter", "mute"]
        case .systemDetails: return ["sip", "csr", "macos", "sensor id", "processor", "memory"]
        }
    }

    /// Does the sidebar's search find the pane?
    ///
    /// - Parameter query: What's typed.
    /// - Returns: `true` when nothing is typed, or the name or a keyword contains it.
    func matches(_ query: String) -> Bool {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        return query.isEmpty || ([title.lowercased()] + keywords).contains { $0.contains(query) }
    }
}


// MARK: - Pieces
/// A pane's colored tile with its white symbol, as System Settings draws them.
struct SettingsIconTile: View {
    let pane: SettingsPane
    var size: CGFloat = 22

    var body: some View {
        Image(systemName: pane.symbol)
            .font(.system(size: size * 0.52, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(pane.tint.gradient, in: RoundedRectangle(cornerRadius: size * 0.26, style: .continuous))
            .accessibilityHidden(true)
    }
}


/// The top of every pane, as System Settings' panes start: a small tile beside the pane's name and what it's for.
struct SettingsPaneHeader: View {
    let pane: SettingsPane
    
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            SettingsIconTile(pane: pane, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(pane.title).font(.headline)
                /// Wraps to the pane's width. Not fixed to its ideal height: a split view measures the pane at a tiny
                /// width first, and the text, one word a line, would push the whole window's content up.
                Text(pane.summary)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
    }
}


/// The sidebar's Security Extension card: its status under its name, as System Settings shows the Apple Account.
struct SettingsStatusCard: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager

    var body: some View {
        let requirements = systemExtensionManager.requirements
        HStack(spacing: 10) {
            SettingsIconTile(pane: .securityExtension, size: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text("Security Extension").fontWeight(.semibold)
                Text(requirements.isReady ? "Ready" : requirements.isSettled
                     ? requirements.nextStep?.title ?? "Ready" : "Checking…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 4)
    }
}


/// The sidebar's search field, as System Settings draws it.
struct SettingsSearchField: View {
    @Binding var text: String
    /// The field's placeholder.
    var prompt = "Search"
    
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            /// The label hidden, the prompt the placeholder: in a form, a TextField's title is a label to its left,
            /// which leaves the field itself a sliver at the right.
            TextField(text: $text, prompt: Text(prompt)) { Text(prompt) }
                .labelsHidden()
                .textFieldStyle(.plain)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Clear the search")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
    }
}


/// A form row's small colored tile, as System Settings starts its rows: a white symbol on a color.
struct SettingsRowIcon: View {
    let symbol: String
    let tint: Color

    /// - Parameters:
    ///   - symbol: The SF Symbol.
    ///   - tint: The tile's color.
    init(_ symbol: String, _ tint: Color) {
        self.symbol = symbol
        self.tint = tint
    }

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 11.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 22, height: 22)
            .background(tint.gradient, in: RoundedRectangle(cornerRadius: 5.5, style: .continuous))
            .accessibilityHidden(true)
    }
}


/// A form row's label with its tile: the name, and what it does underneath when there's more to say.
struct SettingsIconLabel: View {
    let title: String
    var detail: String?
    let icon: SettingsRowIcon

    /// - Parameters:
    ///   - title: The row's name.
    ///   - detail: What it does, if anything.
    ///   - symbol: The tile's SF Symbol.
    ///   - tint: The tile's color.
    init(_ title: String, detail: String? = nil, symbol: String, tint: Color) {
        self.title = title
        self.detail = detail
        self.icon = SettingsRowIcon(symbol, tint)
    }

    var body: some View {
        HStack(spacing: 10) {
            icon
            if let detail {
                SettingsLabel(title, detail: detail)
            } else {
                Text(title)
            }
        }
    }
}


/// Copies a string, then says so for a moment.
struct SettingsCopyButton: View {
    let text: String
    /// What's copied, for the button's help and VoiceOver, such as "the Sensor ID".
    let what: String
    /// A title beside the symbol, or the symbol alone.
    var title: String?
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
        } label: {
            if let title {
                Label(copied ? "Copied" : title, systemImage: copied ? "checkmark" : "doc.on.doc")
            } else {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
        }
        .buttonStyle(CopyButtonStyle(titled: title != nil))
        .help(copied ? "Copied" : "Copy \(what)")
        .accessibilityLabel("Copy \(what)")
    }
}


/// A titled copy button is a small bordered one, and a lone symbol is borderless, as System Settings draws them.
private struct CopyButtonStyle: PrimitiveButtonStyle {
    let titled: Bool

    func makeBody(configuration: Configuration) -> some View {
        if titled {
            Button(configuration).buttonStyle(.bordered).controlSize(.small)
        } else {
            Button(configuration).buttonStyle(.borderless)
        }
    }
}


// MARK: - Pane containers
/// A pane as a grouped form, as System Settings' panes are: the header, then the pane's sections.
struct SettingsForm<Content: View>: View {
    let pane: SettingsPane
    @ViewBuilder let content: Content

    var body: some View {
        Form {
            Section { SettingsPaneHeader(pane: pane) }
            content
        }
        .formStyle(.grouped)
    }
}


/// A pane whose view lays itself out (and scrolls), under the header.
struct SettingsPage<Content: View>: View {
    let pane: SettingsPane
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SettingsPaneHeader(pane: pane)
                .padding(12)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.separator))
            content
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
