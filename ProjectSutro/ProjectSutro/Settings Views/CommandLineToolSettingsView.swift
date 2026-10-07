//
//  CommandLineToolSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
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
            VStack(alignment: .leading) {
                Text("**Command line tool**").font(.title2)
                GroupBox {
                    if let inspection = installer.inspection {
                        VStack(alignment: .leading, spacing: 10) {
                            CommandLineToolStatusView(inspection: inspection)
                            Divider()
                            actions(for: inspection).frame(maxWidth: .infinity, alignment: .center)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        ProgressView().controlSize(.small).frame(maxWidth: .infinity)
                    }
                }
                
                Divider().padding(.bottom)
                
                Text("**Usage**").font(.title2)
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        usage("sudo macmonitor stream", "Mac Monitor's default events, as text")
                        usage("sudo macmonitor stream exec | jq -c .", "Only exec events, as JSONL")
                        usage("sudo macmonitor mute list", "The saved mute set Mac Monitor and macmonitor share")
                        usage("macmonitor help", "Every command and option")
                        Divider()
                        Text("Without the link, run the tool by its full path:")
                        Text(verbatim: "sudo \"\(toolPath)\" stream")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .onAppear { installer.refresh() }
        .alert("Command line tool", isPresented: Binding(get: { installer.failure != nil },
                                                          set: { if !$0 { installer.failure = nil } }),
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(installer.failure ?? "") })
    }
    
    /// The buttons for what may be done now: Install…, Update… or Repair…, and Remove….
    ///
    /// - Parameter inspection: What's there.
    /// - Returns: The buttons, disabled while a change waits on the password prompt.
    private func actions(for inspection: CommandLineToolLink.Inspection) -> some View {
        HStack {
            if inspection.plan(.install) != nil {
                Button(installTitle(for: inspection.link)) { installer.perform(.install, through: systemExtensionManager) }
                    .help("Asks for an administrator password, then links \(inspection.linkPath) to this copy's tool.")
            }
            if inspection.plan(.remove) != nil {
                Button("Remove…") { installer.perform(.remove, through: systemExtensionManager) }
                    .buttonStyle(.borderedProminent).tint(.pink).opacity(0.8)
                    .help("Asks for an administrator password, then removes Mac Monitor's link.")
            }
            if installer.isChanging { ProgressView().controlSize(.small) }
            Button("Look Again") { installer.refresh() }
        }
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
    
    /// One usage example.
    ///
    /// - Parameters:
    ///   - command: What's typed.
    ///   - meaning: What it does.
    /// - Returns: The row.
    private func usage(_ command: String, _ meaning: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(verbatim: command).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                .frame(width: 330, alignment: .leading)
            Text(meaning).foregroundStyle(.secondary)
        }
    }
}


// MARK: - Status
/// What's at `/usr/local/bin/macmonitor`, why Install isn't offered, and any warning about the link's directory.
struct CommandLineToolStatusView: View {
    let inspection: CommandLineToolLink.Inspection
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(inspection.summary).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: icon.name).foregroundStyle(icon.color)
            }
            .font(.title3)
            .textSelection(.enabled)
            if let hint = inspection.hint {
                Text(hint).foregroundStyle(.secondary)
            }
            
            if inspection.link == .current, case .success(let tool) = inspection.tool {
                Text(verbatim: "\(inspection.linkPath) → \(tool)")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
            if case .failure(let refusal) = inspection.tool {
                warning(inspection.link == .current ? "The linked tool can't be trusted. \(refusal)"
                        : "Install is unavailable. \(refusal)")
            }
            if let binDirectoryWarning = inspection.binDirectoryWarning {
                warning(binDirectoryWarning)
            }
        }
    }
    
    /// The status icon and its color.
    private var icon: (name: String, color: Color) {
        switch inspection.link {
        case .current: return ("checkmark.circle.fill", .green)
        case .absent: return ("circle.dashed", .secondary)
        case .elsewhere, .broken: return ("exclamationmark.triangle.fill", .yellow)
        case .foreign, .unusableDirectory: return ("xmark.octagon.fill", .secondary)
        }
    }
    
    /// A warning line.
    ///
    /// - Parameter text: What to say.
    /// - Returns: The line.
    private func warning(_ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette)
                .foregroundStyle(.black, .yellow)
        }
        .textSelection(.enabled)
    }
}
