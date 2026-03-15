//
//  SystemBTMAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemBTMAddMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false

    var event: ESLaunchItemAddEvent {
        esSystemEvent.event.btm_launch_item_add!
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading) {
                // MARK: Event label
                BTMLaunchItemAddEventLabelView(message: esSystemEvent)
                    .font(.title2)

                GroupBox {
                    VStack(alignment: .leading) {
                        HStack {
                            Text("\u{2022} **Type:**")
                            GroupBox {
                                Text(event.item.item_type_string)
                                    .monospaced()
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Executable path:**")
                            GroupBox {
                                Text(event.executable_path)
                                    .monospaced()
                            }
                        }

                        HStack {
                            Text("\u{2022} **Is legacy:**")
                            GroupBox {
                                Text("`\(String(event.item.legacy))`")
                            }

                            Text("\u{2022} **Is managed:**")
                            GroupBox {
                                Text(String(event.item.managed))
                                    .monospaced()
                            }
                        }

                        let itemName = URL(fileURLWithPath: event.item.item_path).lastPathComponent
                        if !itemName.isEmpty {
                            HStack {
                                Text("\u{2022} **Item name:**")
                                GroupBox {
                                    Text(itemName)
                                        .monospaced()
                                }
                            }
                        }

                        HStack {
                            Text("\u{2022} **Item path:**")
                            GroupBox {
                                Text("`\(event.item.item_path)`")
                                    .lineLimit(5)
                            }
                        }

                        if let appPath = event.item.app_path, !appPath.isEmpty {
                            Divider()
                            
                            Label("Registering application", systemImage: "plus.app")
                                .bold()
                                .font(.title3)
                                .padding([.top, .leading], 5.0)

                            HStack {
                                Text("\u{2022} **App path:**")
                                GroupBox {
                                    Text("`\(appPath)`")
                                        .lineLimit(20)
                                }
                            }

                            if let app = event.app, let teamId = app.team_id {
                                HStack {
                                    Text("\u{2022} **App Team ID:**")
                                    GroupBox {
                                        Text(teamId)
                                            .monospaced()
                                            .lineLimit(20)
                                    }
                                }
                            }

                            if let app = event.app, let signingId = app.signing_id {
                                HStack {
                                    Text("\u{2022} **App Signing ID:**")
                                    GroupBox {
                                        Text(signingId)
                                            .monospaced()
                                            .lineLimit(20)
                                    }
                                }
                            }
                        }

                        if let instigator = event.instigator,
                           let instigatingPath = instigator.executable?.path,
                           !instigatingPath.isEmpty {

                            Divider()
                            
                            Label("Instigator", systemImage: "app.connected.to.app.below.fill")
                                .bold()
                                .font(.title3)
                                .padding([.top, .leading], 5.0)

                            HStack {
                                Text("\u{2022} **Instigator path:**")
                                GroupBox {
                                    Text("`\(instigatingPath)`")
                                        .lineLimit(20)
                                }
                            }

                            if let teamId = instigator.team_id {
                                HStack {
                                    Text("\u{2022} **Instigator Team ID:**")
                                    GroupBox {
                                        Text(teamId)
                                            .monospaced()
                                            .lineLimit(20)
                                    }
                                }
                            }

                            if let signingId = instigator.signing_id {
                                HStack {
                                    Text("\u{2022} **Instigator Signing ID:**")
                                    GroupBox {
                                        Text(signingId)
                                            .monospaced()
                                            .lineLimit(20)
                                    }
                                }
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Divider()

                Label("**Context items**", systemImage: "folder.badge.plus")
                    .font(.title2)
                    .padding(.leading, 5)

                GroupBox {
                    HStack {
                        Button("**Audit tokens**") {
                            showAuditTokens.toggle()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .sheet(isPresented: $showAuditTokens) {
            VStack {
                AuditTokenView(
                    audit_token: esSystemEvent.process.audit_token_string,
                    responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                    parent_audit_token: esSystemEvent.process.parent_audit_token_string
                )
                Button("**Dismiss**") {
                    showAuditTokens.toggle()
                }
                .padding(.bottom)
            }
            .padding()
        }
    }
}
