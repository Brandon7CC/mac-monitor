//
//  SystemInitatingProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Initiating process
/// Event Facts' Parent tab: the message's details, then the process that caused the event, its launched-by parent,
/// how it's signed, and its audit tokens.
struct SystemInitiatingProcessView: View {
    var selectedMessage: ESMessage
    @State private var showAuditTokens: Bool = false

    var body: some View {
        let process = selectedMessage.process
        List {
            VStack(alignment: .leading) {
                MessageDetailsHeader(message: selectedMessage) {
                    HStack {
                        Text("\u{2022} **Resulting event type:**")
                        GroupBox {
                            SystemEventTypeLabel(message: selectedMessage)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }

                FactsBox {
                    HStack {
                        Text("\u{2022} **Parent PID:**")
                        GroupBox {
                            Text("`\(String(process.pid))`")
                        }

                        HStack {
                            Image(systemName: "person.fill")
                            Text("**Parent user:**")
                            UserFact(process: process)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }

                    FactRow(name: "Parent process name", value: process.executable?.name ?? "")
                    /// The process row may be shared: its age is the event's.
                    if let age = selectedMessage.processAgeText {
                        FactRow(name: "Parent process age", value: age)
                    }
                    FactRow(name: "Parent process path", value: process.executable?.path ?? "")
                }

                // MARK: Launched by parent
                LaunchedByParentFacts(message: selectedMessage)

                Label("**Code signing details**", systemImage: "signature")
                    .font(.title2)
                    .padding([.leading], 5.0)
                FactsBox {
                    SigningIDFact(process: process)
                    CDHashFact(process: process)
                }

                Divider()

                Group {
                    Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
                    GroupBox {
                        HStack {
                            Button("**Audit tokens**") {
                                showAuditTokens.toggle()
                            }
                        }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
                    }
                }
            }
        }.frame(maxHeight: .infinity, alignment: .topLeading)
            .sheet(isPresented: $showAuditTokens) {
                AuditTokenView(process: process)
                Button("**Dismiss**") {
                    showAuditTokens.toggle()
                }.padding(.bottom)
            }
    }
}
