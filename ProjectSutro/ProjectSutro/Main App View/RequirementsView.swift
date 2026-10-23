//
//  RequirementsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/22/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Requirements
/// The requirements checklist: what Mac Monitor needs before it can talk to Endpoint Security, each with a check or a
/// cross, and a button that opens the place to fix it. It shows on its own when something is missing, and Settings ▸
/// Security Extension shows the same rows. Mac Monitor looks again whenever it comes to the front, so the rows turn to
/// checks as the user fixes them.
struct RequirementsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let requirements = systemExtensionManager.requirements
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                AppIcon()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Requirements").font(.title2.bold())
                    Text(requirements.isReady
                         ? "Mac Monitor can talk to Endpoint Security. Start a trace whenever you like."
                         : "These are required for Mac Monitor to talk to Endpoint Security.")
                        .foregroundStyle(.secondary)
                }
            }
            RequirementRows(rows: requirements.rows)
            HStack {
                Spacer()
                if requirements.isReady {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                } else {
                    Button("Later") { dismiss() }.keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}


// MARK: - Rows
/// Requirements as a grouped list, as the checklist and Settings ▸ Security Extension show them.
struct RequirementRows: View {
    let rows: [SetupRequirements.Row]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(rows) { row in
                if row.kind != rows.first?.kind { Divider().padding(.leading, 48) }
                RequirementRow(row: row)
            }
        }
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator))
    }
}


/// One requirement: its status, what it is, and the button that fixes it.
struct RequirementRow: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    let row: SetupRequirements.Row
    /// Pad the row itself: in a list of its own, not in a form, whose rows are padded already.
    var padded = true

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            RequirementStatusIcon(status: row.status).padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                Text(row.title).fontWeight(.semibold)
                    .foregroundStyle(row.status == .pending ? .secondary : .primary)
                Text(row.detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 8)
            if let action = row.action {
                Button(RequirementActions.title(of: action)) {
                    RequirementActions.perform(action, with: systemExtensionManager)
                }
            }
        }
        .padding(.vertical, padded ? 12 : 2)
        .padding(.horizontal, padded ? 14 : 0)
    }
}


/// A requirement's status: never color alone, each has its own shape.
struct RequirementStatusIcon: View {
    let status: SetupRequirements.Status

    var body: some View {
        switch status {
        case .done: symbol("checkmark.circle.fill", .green).accessibilityLabel("Done")
        case .needed: symbol("xmark.circle.fill", .red).accessibilityLabel("Needs you")
        case .restart: symbol("arrow.clockwise.circle.fill", .orange).accessibilityLabel("Restart needed")
        case .pending:
            Image(systemName: "circle.dashed").foregroundStyle(.secondary).accessibilityLabel("Not checked yet")
        }
    }

    /// A filled circle symbol: white on a color.
    ///
    /// - Parameters:
    ///   - name: The symbol's name.
    ///   - color: The circle's color.
    /// - Returns: The image.
    private func symbol(_ name: String, _ color: Color) -> some View {
        Image(systemName: name).symbolRenderingMode(.palette).foregroundStyle(.white, color)
    }
}


// MARK: - Actions
/// What a requirement's button does.
enum RequirementActions {
    /// System Settings ▸ Privacy & Security ▸ Full Disk Access.
    static let fullDiskAccess = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
    /// Is this macOS 15 or later, where extensions are allowed in General ▸ Login Items & Extensions?
    static let hasExtensionsPane = ProcessInfo.processInfo.isOperatingSystemAtLeast(
        OperatingSystemVersion(majorVersion: 15, minorVersion: 0, patchVersion: 0))
    /// Where the Security Extension is allowed. On macOS 15 and later, Login Items & Extensions' list of Endpoint
    /// Security extensions, which has Mac Monitor's switch: the pane reads `extensionPointIdentifier` from the link.
    /// Before, Privacy & Security, which has the Allow button.
    static var extensions: URL {
        hasExtensionsPane
            ? URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier="
                    + "com.apple.system_extension.endpoint_security.extension-point")!
            : URL(string: "x-apple.systempreferences:com.apple.preference.security?General")!
    }

    /// A button's title.
    ///
    /// - Parameter action: The action.
    /// - Returns: Such as "Open Full Disk Access".
    static func title(of action: SetupRequirements.Action) -> String {
        switch action {
        case .showInFinder: return "Show in Finder"
        case .installExtension: return "Install"
        case .openExtensions:
            return hasExtensionsPane ? "Open Endpoint Security Extensions" : "Open Privacy & Security"
        case .openFullDiskAccess: return "Open Full Disk Access"
        }
    }

    /// Do it.
    ///
    /// - Parameters:
    ///   - action: The action.
    ///   - manager: The Security Extension's manager, to install it.
    static func perform(_ action: SetupRequirements.Action, with manager: EndpointSecurityManager) {
        switch action {
        case .showInFinder: NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
        case .installExtension: manager.activateSystemExtension()
        case .openExtensions: NSWorkspace.shared.open(extensions)
        case .openFullDiskAccess: NSWorkspace.shared.open(fullDiskAccess)
        }
    }
}
