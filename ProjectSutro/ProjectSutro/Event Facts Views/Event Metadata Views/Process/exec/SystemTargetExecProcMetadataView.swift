//
//  SystemTargetExecProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct EntitlementLabelView: View {
    var keyString: String
    
    var body: some View {
        Group {
            HStack {
                Text("**`\(keyString)`**")
            }.padding(5.0)
        }.background(
            RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(.red).opacity(0.4)
        )
    }
}



// MARK: - Exec event metadata
struct SystemTargetExecProcMetadataView: View {
    var selectedMessage: ESMessage

    @State private var showAuditTokens: Bool = false
    @State private var showEnvVars: Bool = false
    @State private var showXPCServiceName: Bool = false
    @State private var showFDs: Bool = false
    
    private var event: ESProcessExecEvent {
        selectedMessage.event.exec!
    }
    
    private var initiatingProc: ESProcess {
        selectedMessage.process
    }
    
    private var targetProcess: ESProcess {
        event.target
    }
    
    private var procPath: String {
        event.target.executable?.path ?? ""
    }
    
    private var procName: String {
        return URL(
            string: event.target.executable?.path ?? ""
        )?.lastPathComponent ?? ""
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
    
    private var hasXPCServiceName: Bool {
        event.env.contains("XPC_SERVICE_NAME") && !event.env.contains("XPC_SERVICE_NAME=0")
    }
    
    var body: some View {
        
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
                    
                    
                    // MARK: Entitlements
                    if event.target.allow_jit || event.target.get_task_allow || event.target.rootless {
                        Divider().padding(.top)
                        ScrollView(.horizontal) {
                            HStack {
                                if event.target.allow_jit {
                                    EntitlementLabelView(keyString: "com.apple.security.cs.allow-jit")
                                }
                                if event.target.get_task_allow {
                                    EntitlementLabelView(keyString: "com.apple.security.get-task-allow")
                                }
                                if event.target.rootless {
                                    EntitlementLabelView(keyString: "com.apple.rootless.restricted-nvram-variables.heritable")
                                }
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
                        
                        // MARK: Signing ID
                        HStack {
                            if event.target.signing_id != nil && event.target.signing_id! != "Unknown" {
                                Text("\u{2022} **Process signing ID:**")
                                GroupBox {
                                    VStack(alignment: .leading) {
                                        Text("`\(event.target.signing_id!)`")
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
                        if event.target.team_id != nil {
                            HStack {
                                Text("\u{2022} **Team ID:**")
                                GroupBox {
                                    VStack(alignment: .leading) {
                                        Text("`\(event.target.team_id!)`")
                                    }
                                }
                            }
                        }
                        
                        // MARK: CD Hash
                        if event.target.signing_id != nil && !event.target.signing_id!.isEmpty {
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
                    
                    if hasXPCServiceName {
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
                XPCMetadataView(execEvent: event, envVars: event.env)
                
            }.frame(maxWidth: 1000.0, maxHeight: .infinity).padding(.all)
            
            Button("**Dismiss**") {
                showXPCServiceName.toggle()
            }.padding(.bottom)
        }
    }
}
