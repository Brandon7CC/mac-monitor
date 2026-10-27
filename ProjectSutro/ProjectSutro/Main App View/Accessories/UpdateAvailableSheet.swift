//
//  UpdateAvailableSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/5/25.
//

import SwiftUI
import SutroESFramework

/// Offers an available update as a Mac app's updater does: what's new, then Skip This Version, Remind Me Later or
/// Install and Reopen. While it installs, it lists the steps and how far along the install is.
struct UpdateAvailableSheet: View {
    let updateDetails: UpdateDetails
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss
    /// The version Skip This Version skipped. The update check at launch doesn't offer it again.
    @AppStorage(Self.skippedVersionKey) private var skippedVersion = ""
    /// Why the update wasn't installed. Shows the failure alert.
    @State private var failure: UpdateFailure?

    /// Where the skipped version is kept.
    static let skippedVersionKey = "updateSkippedVersion"

    /// The steps the install lists, by ``UpdateProgress/step``.
    private static let steps = ["Downloading", "Checking the signature", "Installing", "Reopening Mac Monitor"]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let progress = systemExtensionManager.installProgress {
                installing(progress)
            } else {
                offer
            }
        }
        .padding(24)
        .frame(width: 560)
        .interactiveDismissDisabled(systemExtensionManager.installProgress != nil)
        .alert(failure == .notAdministrator ? "An administrator has to install updates"
                                            : "The update couldn't be installed",
               isPresented: Binding { failure != nil } set: { if !$0 { failure = nil } }, presenting: failure) { _ in
            Button("Open Releases Page") { NSWorkspace.shared.open(releasePage) }
            Button("OK", role: .cancel) {}
        } message: { failure in
            Text(failure.message)
        }
    }

    /// The release's page on GitHub.
    private var releasePage: URL {
        ReleaseNotes.releasesPage.appendingPathComponent("tag/\(updateDetails.version)")
    }

    /// Mac Monitor's icon beside a title and the lines under it.
    ///
    /// - Parameters:
    ///   - title: What the sheet says.
    ///   - lines: The lines under it.
    /// - Returns: The header.
    private func header(_ title: String, @ViewBuilder lines: () -> some View) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 64, height: 64)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.headline)
                lines()
            }
        }
    }

    // MARK: - Offer
    private var offer: some View {
        Group {
            header("A new version of Mac Monitor is available") {
                Text("Mac Monitor \(updateDetails.number) is available. You have \(ReleaseNotes.version).")
                HStack(spacing: 4) {
                    if let day = updateDetails.releaseDay() { Text("Released \(day) ·").foregroundStyle(.secondary) }
                    Link("View on GitHub", destination: releasePage)
                }
            }

            Text("What's New").font(.headline)
            ScrollView {
                Text(ReleaseNotesText.attributed(updateDetails.releaseNotes ?? "This release has no notes."))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(height: 260)
            .background(Color(NSColor.textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.3), lineWidth: 1))

            HStack {
                Button("Skip This Version") {
                    skippedVersion = updateDetails.version
                    dismiss()
                }
                Spacer()
                Button("Remind Me Later") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Install and Reopen", action: install)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    // MARK: - Installing
    /// - Parameter progress: Where the install is.
    /// - Returns: The steps, with how far along the install is.
    private func installing(_ progress: UpdateProgress) -> some View {
        Group {
            header("Installing Mac Monitor \(updateDetails.number)") {
                Text("Mac Monitor quits and reopens when it's done.").foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                ProgressView(value: progress.fraction)
                Text(progress.fraction, format: .percent.precision(.fractionLength(0)))
                    .monospacedDigit()
                    .frame(width: 40, alignment: .trailing)
            }
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Self.steps.indices, id: \.self) { index in
                    step(index, at: progress)
                }
            }
        }
    }

    /// One step of the install: done, under way, or still to come.
    ///
    /// - Parameters:
    ///   - index: The step.
    ///   - progress: Where the install is.
    /// - Returns: The step's row.
    @ViewBuilder
    private func step(_ index: Int, at progress: UpdateProgress) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Group {
                if index < progress.step {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                } else if index == progress.step {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "circle").foregroundStyle(.tertiary)
                }
            }
            .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.steps[index]).fontWeight(index == progress.step ? .semibold : .regular)
                    .foregroundStyle(index > progress.step ? .secondary : .primary)
                switch index {
                case 0:
                    Text("Mac-Monitor.pkg from the \(updateDetails.version) release on GitHub")
                        .foregroundStyle(.secondary)
                case 1:
                    Text("Gatekeeper, and team ID \(SensorXPC.teamID)").foregroundStyle(.secondary)
                default:
                    EmptyView()
                }
            }
        }
    }

    // MARK: - Actions
    /// Install the update, once an administrator is running Mac Monitor. The Security Extension checks again.
    private func install() {
        guard AdministratorCheck.openDirectory.isAdministrator(getuid()) else { return failure = .notAdministrator }
        systemExtensionManager.installUpdate { failure in
            guard let failure else { return reopen() }
            self.failure = failure
        }
    }

    /// Quit and reopen once the update is installed. Skip the "warn before quitting" prompt: the relaunch only waits
    /// 10 seconds for this process to exit.
    ///
    /// Reopening shows for a second, then the sheet closes. AppKit refuses to quit, with a beep, while a sheet is still
    /// closing, so quitting waits half a second more.
    private func reopen() {
        systemExtensionManager.requestAgentRelaunch()
        UserDefaults.standard.set(true, forKey: "lifecycleQuitInternal")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            dismiss()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { NSApplication.shared.terminate(nil) }
        }
    }
}


// MARK: - Check results
extension View {
    /// Shows how a check for updates went, the same from Mac Monitor ▸ Check for Updates and from Settings ▸ General ▸
    /// Check Now: a newer release opens ``UpdateAvailableSheet``, and otherwise an alert says Mac Monitor is up to date
    /// or GitHub couldn't be reached.
    ///
    /// - Parameter check: The check to show. Closing the sheet or the alert sets it back to `nil`.
    /// - Returns: The view, presenting the result.
    func updateCheckResult(_ check: Binding<UpdateCheck?>) -> some View {
        modifier(UpdateCheckResult(check: check))
    }
}


/// ``SwiftUI/View/updateCheckResult(_:)``'s sheet and alert.
private struct UpdateCheckResult: ViewModifier {
    @Binding var check: UpdateCheck?

    func body(content: Content) -> some View {
        content
            .sheet(item: newer) { UpdateAvailableSheet(updateDetails: $0) }
            .onChange(of: noUpdate) { failed in
                guard let failed else { return }
                DispatchQueue.main.async { showNoUpdate(failed: failed) }
            }
    }

    /// The release a check found, while its sheet is open.
    private var newer: Binding<UpdateDetails?> {
        Binding(get: { check?.newerRelease }, set: { if $0 == nil { check = nil } })
    }

    /// Did a check that found nothing newer fail? `nil` while there's no such check to show.
    private var noUpdate: Bool? {
        switch check {
        case .upToDate: return false
        case .failed: return true
        case .newer, nil: return nil
        }
    }

    /// Say there's no update, or that the check failed, in an app-modal `NSAlert`. On macOS 27 an alert shown as a
    /// window's sheet, SwiftUI's in Settings or an `NSAlert`'s, leaves out Mac Monitor's icon.
    ///
    /// - Parameter failed: Did the check fail?
    private func showNoUpdate(failed: Bool) {
        let alert = NSAlert()
        alert.messageText = failed ? "No internet connection" : "Mac Monitor is up to date"
        alert.informativeText = failed ? "Mac Monitor couldn't reach GitHub to check for updates."
            : "\(ReleaseNotes.version) is the newest version."
        alert.addButton(withTitle: "OK")
        alert.runModal()
        check = nil
    }
}


private extension UpdateCheck {
    /// The release a ``newer(_:)`` check found.
    var newerRelease: UpdateDetails? {
        if case .newer(let details) = self { return details }
        return nil
    }
}
