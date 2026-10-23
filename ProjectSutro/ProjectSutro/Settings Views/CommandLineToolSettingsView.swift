//
//  CommandLineToolSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Settings ▸ Command Line
/// Settings ▸ Command Line: link `macmonitor` into `/usr/local/bin`, so `sudo macmonitor` works in any terminal, or
/// remove the link, through the administrator password prompt. The installer package never links it.
struct CommandLineToolSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @StateObject private var installer = CommandLineToolInstaller()

    /// The tool inside this copy of Mac Monitor, which works without the link.
    private let toolPath = Bundle.main.bundlePath + CommandLineToolLink.toolInBundle

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                SettingsSection("Command line tool") {
                    if let inspection = installer.inspection {
                        CommandLineToolStatusView(inspection: inspection, bundlePath: Bundle.main.bundlePath) {
                            actions(for: inspection)
                        }
                    } else {
                        ProgressView().controlSize(.small).frame(maxWidth: .infinity).padding()
                    }
                }
                if installer.inspection.map({ $0.link != .current }) ?? false {
                    SettingsSection("Run it without installing") {
                        CommandRow(command: "sudo \"\(toolPath)\" stream")
                    }
                }
                SettingsSection("Usage") {
                    VStack(spacing: 0) {
                        CommandRow(command: "sudo macmonitor stream", meaning: "Mac Monitor's default events, as text")
                        Divider()
                        CommandRow(command: "sudo macmonitor stream exec | jq -c .",
                                   meaning: "Only exec events, as JSONL")
                        Divider()
                        CommandRow(command: "sudo macmonitor mute list",
                                   meaning: "The saved mute set Mac Monitor and macmonitor share")
                        Divider()
                        CommandRow(command: "macmonitor help", meaning: "Every command and option")
                    }
                }
            }
            .padding(.vertical, 4)
        }
        .onAppear { installer.refresh() }
        .alert("Command line tool", isPresented: Binding(get: { installer.failure != nil },
                                                          set: { if !$0 { installer.failure = nil } }),
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(installer.failure ?? "") })
    }

    /// The buttons for what may be done now: look again, Remove…, and Install…, Update… or Repair….
    ///
    /// Install… stays visible, disabled, when this copy's tool can't be linked, so it's clear what's missing.
    ///
    /// - Parameter inspection: What's there.
    /// - Returns: The buttons, disabled while a change waits on the password prompt.
    private func actions(for inspection: CommandLineToolLink.Inspection) -> some View {
        HStack(spacing: 8) {
            if installer.isChanging { ProgressView().controlSize(.small) }
            Button { installer.refresh() } label: { Image(systemName: "arrow.clockwise") }
                .help("Look again")
                .accessibilityLabel("Look again")
            if inspection.plan(.remove) != nil {
                Button("Remove…") { installer.perform(.remove, through: systemExtensionManager) }
                    .help("Asks for an administrator password, then removes Mac Monitor's link.")
            }
            if inspection.plan(.install) != nil {
                Button(installTitle(for: inspection.link)) {
                    installer.perform(.install, through: systemExtensionManager)
                }
                    .buttonStyle(.borderedProminent)
                    .help("Asks for an administrator password, then links \(inspection.linkPath) to this copy's tool.")
            } else if inspection.link == .absent {
                Button("Install…") {}.disabled(true)
            }
        }
        .controlSize(.large)
        .disabled(installer.isChanging)
    }

    /// What Install is called for what's there.
    ///
    /// - Parameter link: What's at the link's path.
    /// - Returns: Install…, Update… or Repair….
    private func installTitle(for link: CommandLineToolLink.LinkState) -> String {
        switch link {
        case .elsewhere: return "Update…"
        case .broken: return "Repair…"
        default: return "Install…"
        }
    }
}


// MARK: - Status
/// What's at `/usr/local/bin/macmonitor`, as a title with an icon and the path, the actions beside it, and below it
/// the details, why Install isn't offered, and any warning about the link's directory.
struct CommandLineToolStatusView<Actions: View>: View {
    let inspection: CommandLineToolLink.Inspection
    /// This copy of Mac Monitor.
    let bundlePath: String
    @ViewBuilder let actions: Actions

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                icon.font(.system(size: 24)).frame(width: 28)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.title3.weight(.semibold))
                    Text(verbatim: inspection.link == .current ? "\(inspection.linkPath) → this copy"
                                                                : inspection.linkPath)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer(minLength: 12)
                actions
            }
            .padding(14)

            if let details {
                Divider()
                details
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .padding(EdgeInsets(top: 10, leading: 54, bottom: 12, trailing: 14))
            }
            if case .failure(let refusal) = inspection.tool {
                Callout(title: inspection.link == .current ? "The linked tool can't be trusted"
                                                            : "Can't install from this copy",
                        text: refusal.description)
            }
            if let warning = inspection.binDirectoryWarning {
                Callout(title: "Others can change \(inspection.binDirectory)", text: warning)
            }
        }
    }

    /// The status, in a few words.
    private var title: String {
        switch inspection.link {
        case .absent: return "Not installed"
        case .current: return "Installed"
        case .elsewhere: return "Points at another copy"
        case .broken: return "Points at a missing copy"
        case .foreign: return "Something else is there"
        case .unusableDirectory: return "Can't use \(inspection.binDirectory)"
        }
    }

    /// The status icon.
    @ViewBuilder private var icon: some View {
        switch inspection.link {
        case .current:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .absent:
            Image(systemName: "circle.dashed").foregroundStyle(.secondary)
        case .elsewhere, .broken:
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
        case .foreign, .unusableDirectory:
            Image(systemName: "xmark.octagon.fill").foregroundStyle(.secondary)
        }
    }

    /// What the status means here: where the link points, what the action would do, or why nothing can be done.
    private var details: AnyView? {
        switch inspection.link {
        case .current:
            let code = Font.system(.body, design: .monospaced)
            return AnyView(Text("sudo macmonitor").font(code) + Text(" runs the tool in ")
                           + Text(verbatim: bundlePath).font(code) + Text(", in any terminal."))
        case .elsewhere(let value), .broken(let value):
            return AnyView(Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                GridRow {
                    Text("Links to")
                    Text(verbatim: Self.bundle(of: value)).monospaced().foregroundStyle(.primary)
                }
                GridRow {
                    Text("This copy")
                    Text(verbatim: bundlePath).monospaced().foregroundStyle(.primary)
                }
                if let hint = inspection.hint {
                    GridRow {
                        Color.clear.gridCellUnsizedAxes([.horizontal, .vertical])
                        Text(hint)
                    }
                }
            })
        case .absent:
            return inspection.hint.map { AnyView(Text($0)) }
        case .foreign, .unusableDirectory:
            return AnyView(Text(inspection.summary + (inspection.hint.map { " " + $0 } ?? "")))
        }
    }

    /// The app a link's tool belongs to, or the link's value when it isn't a tool in an app.
    ///
    /// - Parameter tool: A link's value.
    /// - Returns: Such as `/Applications/Mac Monitor.app`.
    static func bundle(of tool: String) -> String {
        tool.hasSuffix(CommandLineToolLink.toolInBundle) ? String(tool.dropLast(CommandLineToolLink.toolInBundle.count))
                                                        : tool
    }
}


// MARK: - Pieces
/// A titled group, as in System Settings.
struct SettingsSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    /// - Parameters:
    ///   - title: The section's title.
    ///   - content: Its rows.
    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline).foregroundStyle(.secondary).padding(.leading, 4)
            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator))
        }
    }
}


/// A warning inside a section: a title and an explanation on a tinted ground.
struct Callout: View {
    let title: String
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.multicolor)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).fontWeight(.semibold)
                Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(.yellow.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        .padding([.horizontal, .bottom], 12)
    }
}


/// A command to type, with what it does and a button that copies it.
struct CommandRow: View {
    let command: String
    var meaning: String?
    @State private var copied = false

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: command).monospaced().textSelection(.enabled)
                if let meaning { Text(meaning).foregroundStyle(.secondary) }
            }
            Spacer(minLength: 8)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help(copied ? "Copied" : "Copy")
            .accessibilityLabel("Copy \(command)")
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 14)
    }
}
