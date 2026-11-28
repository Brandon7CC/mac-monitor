//
//  SystemInitatingProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Initiating process
/// Event Facts' Parent tab: the message's details, then the process that caused the event with its audit tokens, its
/// launched-by parent, and how it's signed, scrolling as a whole (``FactsScroll``).
struct SystemInitiatingProcessView: View {
    var selectedMessage: ESMessage

    var body: some View {
        let process = selectedMessage.process
        FactsScroll {
            MessageDetailsHeader(message: selectedMessage) {
                FactRow {
                    Text("\u{2022} **Resulting event type:**")
                    GroupBox {
                        SystemEventTypeLabel(message: selectedMessage)
                    }
                }
            }

            FactsBox {
                FactRow {
                    Fact("Parent PID", String(process.pid))
                    Image(systemName: "person.fill")
                    Text("**Parent user:**")
                    UserFact(process: process)
                }

                FactRow(name: "Parent process name", value: process.executable?.name)
                /// The process row may be shared: its age is the event's.
                if let age = selectedMessage.processAgeText {
                    FactRow(name: "Parent process age", value: age)
                }
                FactRow(name: "Parent process path", value: process.executable?.path)
                AuditTokenFacts(process: process)
            }

            // MARK: Launched by parent
            LaunchedByParentFacts(message: selectedMessage)

            Label("**Code signing details**", systemImage: "signature")
                .font(.title2)
                .padding([.leading], 5.0)
            FactsBox {
                SigningIDFact(process: process)
                /// A network flow's process has no flags: they're never read for it.
                if !selectedMessage.isNetworkFlow {
                    CodeSigningFlagsFact(flags: process.codesigning_flags)
                }
                CDHashFact(process: process)
            }
        }
    }
}
