//
//  SystemTargetExecProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Exec event metadata
/// What an `exec` event says: the new process image, its command line and XPC service, how it's signed, and what
/// scanning the script it runs found. Its environment, code signing flags and file descriptors are in the card's
/// Details box.
struct SystemTargetExecProcMetadataView: View {
    var selectedMessage: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = selectedMessage.event.exec {
            EventFactsCard(message: selectedMessage, target: event.target) {
                processFacts(event)
                /// The XProtect rules that matched the script the exec runs, when any did: below the facts that name
                /// the script.
                if let scan = event.yara_scan, scan.matched {
                    XProtectScanBox(scan: scan)
                }
                codeSigningFacts(event)
            }
        }
    }

    /// The script the exec runs: the one its record names, or for an applet's stub, which names none, the applet's
    /// main.scpt its scan read. Only an applet's exec has a scan and no script.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The script's path, or `nil` without one.
    private func script(_ event: ESProcessExecEvent) -> String? {
        event.resolved_script_path
            ?? (event.yara_scan == nil ? nil : AppletScript.path(ofBundleExecutable: event.target.executable?.path))
    }

    /// The new process image's name: its path's last component.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The name, or "" without a path.
    private func processName(_ event: ESProcessExecEvent) -> String {
        (event.target.executable?.path ?? "").lastPathComponent
    }

    /// The new process image: when it started, its user, its name and IDs, its path, command line, executable age,
    /// script, where it was downloaded from, working directory, TTY and XPC service name.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The facts, in two boxes.
    @ViewBuilder
    private func processFacts(_ event: ESProcessExecEvent) -> some View {
        FactsBox {
            ScrollView(.horizontal) {
                /// The target row may be shared: its age is the exec's.
                ProcessStartFacts(process: event.target, ageText: event.targetAgeText)
            }
            HStack {
                Label("**User:**", systemImage: "person.fill")
                UserFact(process: event.target)
            }
        }

        FactsBox {
            ScrollView(.horizontal) {
                ProcessIDFacts(process: event.target, name: processName(event)) {
                    Fact("Session", String(event.target.session_id))
                    // MARK: Launched-by parent and group leader
                    AdditionalProcMetadataView(selectedMessage: selectedMessage)
                }
            }

            FactRow(name: "Process path", value: event.target.executable?.path ?? "")
            FactRow(name: "Command line", value: event.command_line ?? "", stacked: true)

            // MARK: Executable age
            if let age = event.executableAgeText {
                HStack {
                    Text("\u{2022} **Executable age:**")
                    GroupBox {
                        Label("\(age) old at exec",
                              systemImage: event.isNewExecutable ? "clock.badge.exclamationmark" : "clock")
                            .foregroundStyle(event.isNewExecutable ? .orange : .primary)
                    }
                }
            }

            if let script = script(event) {
                FactRow(name: "Script", value: script, stacked: true)
            }
            if let origins = event.where_froms, !origins.isEmpty {
                FactRow(name: "Download origin", value: origins.joined(separator: "\n"), stacked: true)
            }
            if let cwdPath = event.cwd?.path, cwdPath.count > 1 {
                FactRow(name: "CWD", value: cwdPath, stacked: true)
            }
            if let ttyPath = event.target.tty?.path {
                FactRow(name: "TTY", value: ttyPath)
            }
            if let serviceName = event.xpcServiceName {
                FactRow(name: "XPC service name", value: serviceName)
            }
        }
    }

    /// How the new process image is signed: its code signing type and flags, signing ID, team ID, code directory hash
    /// and certificate chain.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The facts, in a box.
    @ViewBuilder
    private func codeSigningFacts(_ event: ESProcessExecEvent) -> some View {
        FactsBox {
            Label("**Code signing details**", systemImage: "signature")
                .font(.title3)
                .padding([.leading, .top], 5.0)

            FactsBox {
                FactRow(name: "Code signing type",
                        value: event.target.codeSigningTypeLabel(version: selectedMessage.version))

                // MARK: Code signing flags
                /// The value and how many are set: the Details box's Code signing flags tab lists them.
                FactRow {
                    Fact("Code signing flags",
                         String(format: "0x%08X", UInt32(truncatingIfNeeded: event.target.codesigning_flags)))
                    Text("\(ProcessHelpers.codeSigningFlags(event.target.codesigning_flags).count) set")
                        .foregroundStyle(.secondary)
                }

                SigningIDFact(process: event.target)
                if let teamID = event.target.team_id.nonEmpty {
                    FactRow(name: "Team ID", value: teamID)
                }
                if event.target.signing_id.nonEmpty != nil {
                    CDHashFact(process: event.target)
                }

                // MARK: Cert chain
                if !event.certificate_chain.isEmpty {
                    Text("\u{2022} **Certificate chain:**")
                    ScrollView(.horizontal) {
                        VStack(alignment: .leading) {
                            ForEach(event.certificate_chain, id: \.self) { cert in
                                let summary: String = cert.summary
                                let thumbprint: String = cert.thumbprint
                                GroupBox {
                                    HStack {
                                        Label("`\(summary)`", systemImage: "lock.doc")
                                        Image(systemName: "arrow.right")
                                        Label("`\(thumbprint)`", systemImage: "touchid")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
