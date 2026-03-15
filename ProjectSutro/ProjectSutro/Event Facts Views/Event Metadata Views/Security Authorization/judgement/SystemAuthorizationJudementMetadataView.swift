//
//  SwiftUIView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/28/23.
//

import SwiftUI
import SutroESFramework


struct Result: Identifiable, Hashable {
    let id = UUID()
    var rightName: String
    var ruleClass: String
    var granted: Bool

    init(from description: String) {
        let components = description.components(separatedBy: ", ")
        let rightNameComponent = components.first(where: { $0.contains("Right name") })
        let ruleClassComponent = components.first(where: { $0.contains("Rule class") })
        let grantedComponent = components.first(where: { $0.contains("Granted") })

        self.rightName = rightNameComponent?.components(separatedBy: ": ").last ?? ""
        self.ruleClass = ruleClassComponent?.components(separatedBy: ": ").last ?? ""
        self.granted = Bool(grantedComponent?.components(separatedBy: ": ").last ?? "") ?? false
    }
}

struct AuthJudgeProcsView: View {
    var event: ESAuthorizationJudgementEvent
    
    var body: some View {
        VStack(alignment: .leading) {
            if let instigator = event.instigator,
               let petitioner = event.petitioner,
               let instigatorSigningId = instigator.signing_id,
               let petitionerSigningId = petitioner.signing_id,
               let instigatorExe = instigator.executable,
               let petitionerExe = petitioner.executable {
                
                if instigatorSigningId != petitionerSigningId {
                    HStack {
                        Text("\u{2022} Instigator process name:")
                            .bold()
                        GroupBox {
                            Text(instigatorExe.name)
                                .monospaced()
                        }
                    }
                    
                    if !instigatorExe.path.isEmpty {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Instigator process path:")
                                .bold()
                            GroupBox {
                                Text(instigatorExe.path)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .lineLimit(30)
                            }
                        }
                    }

                    HStack {
                        Text("\u{2022} Instigator process signing ID:")
                            .bold()
                        GroupBox {
                            Text(instigatorSigningId)
                                .monospaced()
                        }
                    }
                    
                    Divider().padding(.vertical, 10)
                    
                    HStack {
                        Text("\u{2022} Petitioner process name:")
                            .bold()
                        GroupBox {
                            Text(petitionerExe.name)
                                .monospaced()
                        }
                    }
                    
                    if !petitionerExe.path.isEmpty {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Petitioner process path:")
                                .bold()
                            GroupBox {
                                Text(petitionerExe.path)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .lineLimit(30)
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Petitioner process signing ID:")
                            .bold()
                        GroupBox {
                            Text(petitionerSigningId)
                                .monospaced()
                        }
                    }
                    
                    Divider().padding(.vertical, 10)
                } else {
                    GroupBox {
                        Label("The processes petitioning and instigating are the same:", systemImage: "info.square")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    HStack {
                        Text("\u{2022} Process name:")
                            .bold()
                        GroupBox {
                            Text(instigatorExe.name)
                                .monospaced()
                        }
                    }
                    
                    if !instigatorExe.path.isEmpty {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Process path:")
                                .bold()
                            GroupBox {
                                Text(instigatorExe.path)
                                    .monospaced()
                                    .lineLimit(nil)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Process signing ID:")
                            .bold()
                        GroupBox {
                            Text(instigatorSigningId)
                                .monospaced()
                        }
                    }
                    Divider().padding(.vertical, 10)
                }
            }
        }
    }
}


struct SystemAuthorizationJudgementMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESAuthorizationJudgementEvent {
        esSystemEvent.event.authorization_judgement!
    }
    
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            OrangeEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    AuthJudgeProcsView(event: event)
                    
                    Text("**Results from authorization petition:**")
                    Table(event.results) {
                        TableColumn("Right name") { result in
                            Text("`\(result.right_name)`")
                        }
                        TableColumn("Rule class") { result in
                            Text("`\(result.ruleClassShortName)`")
                        }
                        TableColumn("Granted") { result in
                            Text("`\(result.granted ? "Yes" : "No")`")
                        }
                    }
                    .frame(maxWidth: nil, minHeight: 100.0, maxHeight: nil, alignment: .leading)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding([.leading, .trailing], 10)
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            
            Divider().padding(.vertical, 10)
            
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .sheet(isPresented: $showAuditTokens) {
            VStack {
                AuditTokenView(
                    audit_token: esSystemEvent.process.audit_token_string,
                    responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                    parent_audit_token: esSystemEvent.process.parent_audit_token_string
                )
                Button("Dismiss") {
                    showAuditTokens.toggle()
                }.padding(.bottom)
            }
        }
    }
}
