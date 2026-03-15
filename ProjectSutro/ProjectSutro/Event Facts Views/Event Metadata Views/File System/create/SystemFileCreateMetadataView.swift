//
//  SystemFileCreateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct FileQuarantineStatusLabelView: View {
    var isQuarantined: Int
    
    var quarantinedColor: Color = Color(cgColor: .init(red: 58/255.0, green: 194/255.0, blue: 72/255.0, alpha: 1.0))
    var notQuarantinedColor: Color = Color(cgColor: .init(red: 242/255.0, green: 100/255.0, blue: 90/255.0, alpha: 1.0))
    
    
    var body: some View {
        if isQuarantined != 2 {
            Group {
                HStack {
                    Image(systemName: "lock.shield")
                        .symbolRenderingMode(.palette)
                        .foregroundColor(.black)
                        .font(Font.system(size: 13, weight: .bold))
                    if isQuarantined == 1 {
                        Text("**`Quarantined`**").foregroundColor(.black)
                    } else if isQuarantined == 0 {
                        Text("**`Not quarantined`**").foregroundColor(.black)
                    }
                }.padding(5.0)
            }.background(
                RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(self.isQuarantined == 1 ? quarantinedColor : notQuarantinedColor)
            ).help(self.isQuarantined == 1 ? "This file is quarantined" : "This file is not quarantined")
        }
    }
}

struct SystemFileCreateMetadataView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var create: ESFileCreateEvent? {
        esSystemEvent.event.create
    }
    
    var destinationTypeString: String {
        create?.destination_type_string ?? ""
    }
    
    var createdFileName: String {
        guard let create = create else { return "" }
        switch create.destination {
        case .new_path(let np): return np.filename
        case .existing_file(let f): return URL(fileURLWithPath: f.path).lastPathComponent
        }
    }

    var destinationPath: String {
        guard let create = create else { return "" }
        switch create.destination {
        case .new_path(let np): return "\(np.dir.path)/\(np.filename)"
        case .existing_file(let f): return f.path
        }
    }

    var fileQuarantineEnabled: Bool {
        esSystemEvent.process.file_quarantine_type != .disabled
    }
    
    var fileQuarantineType: Int {
        Int(create?.is_quarantined ?? 0)
    }
    
    var fileIsNotArtifact: Bool {
        let artifacts = [
            ".part",
            ".download"
        ]
        
        for artifact in artifacts {
            if !createdFileName.hasSuffix(artifact) {
                return true
            }
        }
        
        return false
    }
    
    var acl: String? {
        create?.acl
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            FileCreateEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    if fileQuarantineEnabled && fileQuarantineType == 0 && fileIsNotArtifact {
                        GroupBox {
                            HStack {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .symbolRenderingMode(.palette)
                                    .foregroundStyle(.black, .yellow)
                                Text("This file is potentially *not* quarantined by a \"File Quarantine-aware\" application. False positives exist (e.g. if the attribute is quickly deleted) and the existance of the `com.apple.quarantine` extended attribute should be investigated.")
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Type:**")
                        GroupBox {
                            Text("`\(destinationTypeString)`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **File name:**")
                        GroupBox {
                            Text("`\(createdFileName)`")
                        }
                        FileQuarantineStatusLabelView(isQuarantined: fileQuarantineType)
                    }
                    
                    HStack {
                        if FileManager.default
                            .fileExists(atPath: destinationPath) {
                            Label("**File path:**", systemImage: "checkmark.circle")
                                .labelStyle(.titleAndIcon)
                                .help("This file exists.")
                        } else {
                            Label("**File path:**", systemImage: "xmark.circle")
                                .labelStyle(.titleAndIcon)
                                .help("This file no longer exists.")
                        }
                        GroupBox {
                            Text("`\(destinationPath)`")
                                .lineLimit(10)
                        }
                    }
                    
                    if let acl = acl {
                        HStack {
                            Text("\u{2022} **ACL:**")
                            GroupBox {
                                Text("`\(acl.trimmingCharacters(in: .whitespacesAndNewlines))`")
                            }
                        }
                    }
                    
                    if let dest = create?.destination, case .new_path(let newPath) = dest {
                        HStack {
                            Text("\u{2022} **Mode:**")
                            GroupBox {
                                Text("`\(newPath.mode ?? 0)`")
                            }
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            
            Divider()
            
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: esSystemEvent.process.audit_token_string,
                responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                parent_audit_token: esSystemEvent.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}
