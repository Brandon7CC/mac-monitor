//
//  SystemTCCModifyMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//

import SwiftUI
import SutroESFramework


/// What a `tcc_modify` event says: the TCC service, the identity whose right changed and how, and the instigating and
/// responsible processes.
struct SystemTCCModifyMetadataView: View {
    var message: ESMessage
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = message.event.tcc_modify {
            EventFactsCard(message: message) {
                FactsBox {
                    HStack {
                        HStack {
                            Text("\u{2022} **Update type:**")
                            GroupBox {
                                Text("`\(event.updateSuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Reason:**")
                            GroupBox {
                                Text("`\(event.reasonSuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Service name:**")
                            GroupBox {
                                Text("`\(event.service)`")
                            }
                        }
                    }
                    
                    HStack {
                        HStack {
                            Text("\u{2022} **Identity type:**")
                            GroupBox {
                                Text("`\(event.identitySuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Identity:**")
                            GroupBox {
                                Text("`\(event.identity)`")
                            }
                        }
                    }
                    
                    HStack {
                        Label("Right", systemImage: event.rightGranted ? "checkmark.circle" : "xmark.circle")
                            .bold()
                        GroupBox {
                            Text("`\(event.rightSuffix)`")
                        }
                    }
                    
                    if let instigator = event.instigator, let executable = instigator.executable {
                        Divider()
                        processFacts(instigator, executable: executable, role: "Instigator")
                    }
                    
                    if let responsible = event.responsible, let executable = responsible.executable {
                        Divider()
                        processFacts(responsible, executable: executable, role: "Responsible")
                    }
                }
            }
        }
    }

    /// A process behind the change: its name, PID and GID, and its path.
    ///
    /// - Parameters:
    ///   - process: The process.
    ///   - executable: The process's executable.
    ///   - role: The process's part in the change, which titles its facts: "Instigator" or "Responsible".
    /// - Returns: The process's facts under its role.
    private func processFacts(_ process: ESProcess, executable: ESFile, role: String) -> some View {
        VStack(alignment: .leading) {
            Text(role)
                .font(.title3)
                .bold()
            
            HStack {
                Text("\u{2022} **\(role) name:**")
                GroupBox {
                    Text("`\(executable.name)`")
                }
                Text("\u{2022} **PID:**")
                GroupBox {
                    Text("`\(String(process.pid))`")
                }
                Text("\u{2022} **GID:**")
                GroupBox {
                    Text("`\(String(process.group_id))`")
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            
            FactRow(name: "\(role) path", value: executable.path ?? "")
        }
    }
}


// MARK: - TCC names
private extension ESTCCModifyEvent {
    /// The identity's type without its constant's prefix, such as `BUNDLE_ID`.
    var identitySuffix: String { identity_type_string.droppingPrefix("ES_TCC_IDENTITY_TYPE_") }
    /// The update's type without its constant's prefix, such as `MODIFY`.
    var updateSuffix: String { update_type_string.droppingPrefix("ES_TCC_EVENT_TYPE_") }
    /// The right without its constant's prefix, such as `ALLOWED`.
    var rightSuffix: String { right_string.droppingPrefix("ES_TCC_AUTHORIZATION_RIGHT_") }
    /// The reason without its constant's prefix, such as `USER_CONSENT`.
    var reasonSuffix: String { reason_string.droppingPrefix("ES_TCC_AUTHORIZATION_REASON_") }
    /// Was the right granted: anything but `DENIED` or `UNKNOWN`?
    var rightGranted: Bool { rightSuffix != "DENIED" && rightSuffix != "UNKNOWN" }
}
