//
//  SystemTargetExecProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Exec event metadata
struct SystemTargetExecProcMetadataView: View {
    var selectedMessage: ESMessage

    @State private var showAuditTokens: Bool = false
    @State private var showEnvVars: Bool = false
    @State private var showXPCServiceName: Bool = false
    @State private var showFDs: Bool = false
    @State private var showCodeSigningFlags: Bool = false
    
    private var event: ESProcessExecEvent {
        selectedMessage.event.exec!
    }
    
    private var procPath: String {
        event.target.executable?.path ?? ""
    }
    
    private var procName: String {
        (event.target.executable?.path ?? "").lastPathComponent
    }
    
    private var start_time: String {
        event.target.start_time
    }
    
    private var codesigning_type: String {
        if selectedMessage.version >= 10 && event.target.cs_validation_category != 10 {
            if let cs_validation_string = event.target.cs_validation_category_string {
                let stringSuffix = cs_validation_string.trimmingPrefix("ES_CS_VALIDATION_CATEGORY_")
                return "\(stringSuffix) (\(event.target.cs_validation_category))"
            }
        }
        
        return event.target.codesigning_type
    }
    
    /// The flags set in the target's code signing flags, in bit order.
    private var codeSigningFlags: [CodeSigningFlag] {
        ProcessHelpers.codeSigningFlags(event.target.codesigning_flags)
    }

    /// The XPC service the process was started as. Matching whole entries for `XPC_SERVICE_NAME` never found one, so
    /// the XPC sheet never showed.
    private var xpcServiceName: String? {
        event.xpcServiceName
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if selectedMessage.event.exec != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        
        VStack(alignment: .leading) {
            // MARK: Event label
            ExecEventLabelView(message: selectedMessage)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    Group {
                        ScrollView(.horizontal) {
                            HStack {
                                // MARK: Start time
                                Label("**Start time:**", systemImage: "clock")
                                    .padding([.leading], 5.0)
                                GroupBox {
                                    Text("`\(start_time)`")
                                }
                                
                                // MARK: File Quarantine
                                if event.target.file_quarantine_type != "DISABLED" {
                                    FileQuarantineLabelView(
                                        type: event.target.file_quarantine_type
                                    )
                                }
                            }
                        }
                        
                        HStack {
                            Label("**User:**", systemImage: "person.fill")
                                .padding([.leading], 5.0)
                            TargetUserView(selectedMessage: selectedMessage)
                        }


                    }
                }
            }
            
            GroupBox {
                VStack(alignment: .leading) {
                    
                    ScrollView(.horizontal) {
                        HStack {
                            // MARK: Process name
                            Text("\u{2022} **Process name:**")
                            GroupBox {
                                Text("`\(procName)`")
                            }
                            Spacer()
                            // MARK: PID
                            Text("\u{2022} **PID:**")
                            GroupBox {
                                Text("`\(String(event.target.pid))`")
                            }
                            Spacer()
                            // MARK: GID
                            Text("\u{2022} **GID:**")
                            GroupBox {
                                Text("`\(String(event.target.group_id))`")
                            }
                            Spacer()
                            // MARK: `session_id`
                            Text("\u{2022} **Session:**")
                            GroupBox {
                                Text("`\(String(event.target.session_id))`")
                            }
                            
                            // MARK: Group leader
                            AdditionalProcMetadataView(selectedMessage: selectedMessage)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    
                    
                    // MARK: Path
                    HStack {
                        Text("\u{2022} **Process path:**")
                        GroupBox {
                            Text("`\(procPath)`")
                            //                                .frame(maxWidth: .infinity, alignment: .leading)
                                .lineLimit(30)
                        }
                    }
                    
                    // MARK: Command line
                    Text("\u{2022} **Command line:**")
                    GroupBox {
                        Text("`\(event.command_line ?? "")`")
                            .lineLimit(300)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    
                    // MARK: Executable age
                    if let age = event.executableAgeText {
                        HStack {
                            Text("\u{2022} **Executable age:**")
                            GroupBox {
                                Label("Created \(age) before it ran",
                                      systemImage: event.isNewExecutable ? "clock.badge.exclamationmark" : "clock")
                                    .foregroundStyle(event.isNewExecutable ? .orange : .primary)
                            }
                        }
                    }
                    
                    // MARK: Script
                    if let script = event.resolved_script_path {
                        Text("\u{2022} **Script:**")
                        GroupBox {
                            Text(script)
                                .monospaced()
                        }
                    }
                    
                    // MARK: CWD
                    if let cwd = event.cwd,
                       let cwdPath = cwd.path,
                       cwdPath.count > 1 {
                        Text("\u{2022} **CWD:**")
                        GroupBox {
                            Text("`\(cwdPath)`")
                        }
                    }
                    
                    // MARK: TTY
                    if let ttyPath = event.target.tty?.path {
                        HStack {
                            Text("\u{2022} **TTY:**")
                            GroupBox {
                                Text("`\(ttyPath)`")
                                    .lineLimit(10)
                            }
                        }
                    }

                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        GroupBox {
            VStack(alignment: .leading) {
                
                // MARK: Code signing
                Label("**Code signing details**", systemImage: "signature")
                    .font(.title3)
                    .padding([.leading, .top], 5.0)
                
                GroupBox {
                    VStack(alignment: .leading) {
                        
                        
                        HStack {
                            Text("\u{2022} **Code signing type:**")
                            GroupBox {
                                Text("`\(codesigning_type)`")
                            }
                        }
                        
                        // MARK: Code signing flags
                        /// The value and how many are set: the Code signing flags section lists them.
                        HStack {
                            Text("\u{2022} **Code signing flags:**")
                            GroupBox {
                                Text(String(format: "0x%08X",
                                            UInt32(truncatingIfNeeded: event.target.codesigning_flags)))
                                    .monospaced()
                            }
                            Text("\(codeSigningFlags.count) set").foregroundStyle(.secondary)
                        }
                        
                        // MARK: Signing ID
                        HStack {
                            if let signingID = event.target.signing_id.nonEmpty, signingID != "Unknown" {
                                Text("\u{2022} **Process signing ID:**")
                                GroupBox {
                                    VStack(alignment: .leading) {
                                        Text("`\(signingID)`")
                                    }
                                }
                            } else {
                                GroupBox {
                                    Text("Code object is not signed at all")
                                        .frame(alignment: .leading)
                                }
                            }
                            
                        }
                        
                        // MARK: Team ID
                        if let teamID = event.target.team_id.nonEmpty {
                            HStack {
                                Text("\u{2022} **Team ID:**")
                                GroupBox {
                                    VStack(alignment: .leading) {
                                        Text("`\(teamID)`")
                                    }
                                }
                            }
                        }
                        
                        // MARK: CD Hash
                        if event.target.signing_id.nonEmpty != nil {
                            HStack {
                                Text("\u{2022} **`SHA256` Code directory hash:**")
                                GroupBox {
                                    Text("`\(String(event.target.cdhash!))`")
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
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
                    }.frame(maxWidth: .infinity, alignment: .topLeading)
                }
                
            }
        }
        
        // MARK: Code signing flags
        if !codeSigningFlags.isEmpty {
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Label("**Code signing flags**", systemImage: "flag")
                            .font(.title3)
                        Button("\(showCodeSigningFlags ? "Hide" : "Show") code signing flags") {
                            showCodeSigningFlags.toggle()
                        }
                    }

                    if showCodeSigningFlags {
                        GroupBox {
                            Table(codeSigningFlags) {
                                TableColumn("Flag") { flag in
                                    Text(flag.name).monospaced().textSelection(.enabled)
                                }
                                .width(min: 180, ideal: 230)
                                TableColumn("Bit") { flag in
                                    Text(String(format: "0x%08X", flag.bit)).monospaced()
                                }
                                .width(min: 90, ideal: 100, max: 120)
                                TableColumn("Meaning", value: \.summary)
                            }
                            /// Every flag without scrolling: a process has a dozen at most.
                            .frame(height: CGFloat(codeSigningFlags.count) * 26 + 34)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }

        // MARK: File Descriptors
        if !event.fds.isEmpty {
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Label("**File descriptors**", systemImage: "doc.plaintext")
                            .font(.title3)
                        Button("\(showFDs ? "Hide" : "Show") file descriptors") {
                            showFDs.toggle()
                        }
                    }
                    
                    if showFDs {
                        GroupBox {
                            Table(event.fds) {
                                TableColumn("FD", value: \.fd.description)
                                TableColumn("Type", value: \.type)
                                TableColumn("Pipe ID") { fd in
                                    Text(fd.pipe?.pipe_id.description ?? "")
                                }
                            }
                            .frame(height: CGFloat(150))
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        
        Divider()
            .padding([.top, .bottom])
        
        VStack(alignment: .leading) {
            // MARK: Context items
            Label("**Context items**", systemImage: "folder.badge.plus")
                .font(.title2)
                .padding([.leading], 5.0)
            GroupBox {
                HStack {
                    if !event.env.isEmpty {
                        Button {
                            showEnvVars.toggle()
                        } label: {
                            Text("**Environment variables (`\(event.env.count)`)**")
                        }
                    }
                    
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                    
                    if xpcServiceName != nil {
                        Button("**XPC**") {
                            showXPCServiceName.toggle()
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: event.target.audit_token_string,
                responsible_audit_token: event.target.responsible_audit_token_string,
                parent_audit_token: event.target.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }.sheet(isPresented: $showEnvVars) {
            VStack(alignment: .leading) {
                Form {
                    Section {
                        Text("**`\(procName)`'s environment variables:**")
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
        }.sheet(isPresented: $showXPCServiceName) {
            VStack(alignment: .leading) {
                XPCMetadataView(serviceName: xpcServiceName ?? "")
                
            }.frame(maxWidth: 1000.0, maxHeight: .infinity).padding(.all)
            
            Button("**Dismiss**") {
                showXPCServiceName.toggle()
            }.padding(.bottom)
        }
    }
}
