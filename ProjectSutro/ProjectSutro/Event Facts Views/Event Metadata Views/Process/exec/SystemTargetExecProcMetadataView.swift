//
//  SystemTargetExecProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Exec event metadata
/// What an `exec` event says: the new process image, its command line, how it's signed, its code signing flags and
/// file descriptors, and its environment and XPC service in sheets.
struct SystemTargetExecProcMetadataView: View {
    var selectedMessage: ESMessage

    @State private var showTargetAuditTokens: Bool = false
    @State private var showEnvVars: Bool = false
    @State private var showXPCServiceName: Bool = false
    @State private var showFDs: Bool = false
    @State private var showCodeSigningFlags: Bool = false

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = selectedMessage.event.exec {
            EventFactsCard(message: selectedMessage) {
                processFacts(event)
                codeSigningFacts(event)
                codeSigningFlagFacts(event)
                fileDescriptorFacts(event)
            } context: {
                Button("**Target audit tokens**") {
                    showTargetAuditTokens.toggle()
                }
                if !event.env.isEmpty {
                    Button {
                        showEnvVars.toggle()
                    } label: {
                        Text("**Environment variables (`\(event.env.count)`)**")
                    }
                }
                if event.xpcServiceName != nil {
                    Button("**XPC**") {
                        showXPCServiceName.toggle()
                    }
                }
            }.sheet(isPresented: $showTargetAuditTokens) {
                AuditTokenView(process: event.target)
                Button("**Dismiss**") {
                    showTargetAuditTokens.toggle()
                }.padding(.bottom)
            }.sheet(isPresented: $showEnvVars) {
                environmentSheet(event)
            }.sheet(isPresented: $showXPCServiceName) {
                VStack(alignment: .leading) {
                    XPCMetadataView(serviceName: event.xpcServiceName ?? "")
                }.frame(maxWidth: 1000.0, maxHeight: .infinity).padding(.all)

                Button("**Dismiss**") {
                    showXPCServiceName.toggle()
                }.padding(.bottom)
            }
        }
    }

    /// The new process image's name: its path's last component.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The name, or "" without a path.
    private func processName(_ event: ESProcessExecEvent) -> String {
        (event.target.executable?.path ?? "").lastPathComponent
    }

    /// The new process image: when it started, its user, its name and IDs, its path, command line, executable age,
    /// script, working directory and TTY.
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
                    .padding([.leading], 5.0)
                UserFact(process: event.target)
            }
        }

        FactsBox {
            ScrollView(.horizontal) {
                ProcessIDFacts(process: event.target, name: processName(event)) {
                    Text("\u{2022} **Session:**")
                    GroupBox {
                        Text("`\(String(event.target.session_id))`")
                    }
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

            if let script = event.resolved_script_path {
                FactRow(name: "Script", value: script, stacked: true, style: .monospaced)
            }
            if let cwdPath = event.cwd?.path, cwdPath.count > 1 {
                FactRow(name: "CWD", value: cwdPath, stacked: true)
            }
            if let ttyPath = event.target.tty?.path {
                FactRow(name: "TTY", value: ttyPath)
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
                /// The value and how many are set: the Code signing flags section lists them.
                HStack {
                    Text("\u{2022} **Code signing flags:**")
                    GroupBox {
                        Text(String(format: "0x%08X", UInt32(truncatingIfNeeded: event.target.codesigning_flags)))
                            .monospaced()
                    }
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
                        ForEach(event.certificate_chain, id: \.self) { cert in
                            let summary: String = cert.summary
                            let thumbprint: String = cert.thumbprint
                            GroupBox {
                                HStack {
                                    Label("`\(summary)`", systemImage: "lock.doc")
                                    Image(systemName: "arrow.right")
                                    Label("`\(thumbprint)`", systemImage: "touchid")
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
            }
        }
    }

    /// The flags set in the new process image's code signing flags, in bit order, behind a Show button.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The flags in a box, or nothing when none is set.
    @ViewBuilder
    private func codeSigningFlagFacts(_ event: ESProcessExecEvent) -> some View {
        let codeSigningFlags = ProcessHelpers.codeSigningFlags(event.target.codesigning_flags)
        if !codeSigningFlags.isEmpty {
            FactsBox {
                HStack {
                    Label("**Code signing flags**", systemImage: "flag")
                        .font(.title3)
                    Button("\(showCodeSigningFlags ? "Hide" : "Show") code signing flags") {
                        showCodeSigningFlags.toggle()
                    }
                }

                if showCodeSigningFlags {
                    GroupBox {
                        FactsGrid(codeSigningFlags, columns:
                            .init("Flag") { $0.name },
                            .init("Bit") { String(format: "0x%08X", $0.bit) },
                            .init("Meaning", monospaced: false) { $0.summary })
                    }
                }
            }
        }
    }

    /// The new process image's file descriptors, behind a Show button.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The file descriptors in a box, or nothing when the exec has none.
    @ViewBuilder
    private func fileDescriptorFacts(_ event: ESProcessExecEvent) -> some View {
        if !event.fds.isEmpty {
            FactsBox {
                HStack {
                    Label("**File descriptors**", systemImage: "doc.plaintext")
                        .font(.title3)
                    Button("\(showFDs ? "Hide" : "Show") file descriptors") {
                        showFDs.toggle()
                    }
                }

                if showFDs {
                    GroupBox {
                        FactsGrid(event.fds, columns:
                            .init("FD") { $0.fd.description },
                            .init("Type") { $0.type },
                            .init("Pipe ID") { $0.pipe?.pipe_id.description ?? "" })
                    }
                }
            }
        }
    }

    /// The new process image's environment variables, for a sheet.
    ///
    /// - Parameter event: The exec.
    /// - Returns: The variables, one per box, and a Dismiss button.
    @ViewBuilder
    private func environmentSheet(_ event: ESProcessExecEvent) -> some View {
        VStack(alignment: .leading) {
            Form {
                Section {
                    Text("**`\(processName(event))`'s environment variables:**")
                        .font(.title2)
                    Divider()
                    GroupBox {
                        ScrollView {
                            ForEach(event.env, id: \.self) { variable in
                                GroupBox {
                                    Text("`\(variable)`").lineLimit(3).frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        }.frame(maxHeight: 300.0)
                    }
                }
            }
        }.frame(maxWidth: 1000.0, maxHeight: .infinity).padding(.all)

        Button("**Dismiss**") {
            showEnvVars.toggle()
        }.padding(.bottom)
    }
}
