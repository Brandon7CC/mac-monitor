//
//  ProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 7/13/25.
//

import SwiftUI
import SutroESFramework

struct ProcessView: View {
    var message: ESMessage
    var process: ESProcess
    
    var executable: ESFile? {
        process.executable
    }
    
    var processNmae: String {
        executable?.name ?? ""
    }
    
    var processPath: String {
        executable?.path ?? ""
    }
    
    var signingId: String {
        process.signing_id ?? "Unknown"
    }
    
    var cdHash: String {
        process.cdhash!
    }
    
    var codeSigningType: String {
        if message.version >= 10 {
            if let cs_validation_category_string = process.cs_validation_category_string {
                let csSuffix = cs_validation_category_string.trimmingPrefix("ES_CS_VALIDATION_CATEGORY_")
                return "\(csSuffix) (\(process.cs_validation_category ?? 0))"
            }
        }
        
        return process.codesigning_type.rawValue
    }
    
    var body: some View {
        GroupBox {
            VStack(alignment: .leading) {
                HStack {
                    // MARK: Start time
                    Label("**Start time:**", systemImage: "clock")
                    GroupBox {
                        Text("`\(process.start_time.humanFormat())`")
                    }

                    // MARK: File Quarantine
                    if process.file_quarantine_type != .disabled {
                        FileQuarantineLabelView(
                            type: process.file_quarantine_type.rawValue
                        )
                    }
                    
                }
                HStack {
                    Label("**User:**", systemImage: "person.fill")
                    TargetUserView(selectedMessage: message)
                }
               
                
                HStack {
                    Text("\u{2022} **Process name:**")
                    GroupBox {
                        Text("`\(processNmae)`")
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
                
                
                HStack {
                    Text("\u{2022} **Process path:**")
                    GroupBox {
                        Text("`\(processPath)`")
                            .lineLimit(10)
                    }
                }
                
                if let ttyPath = process.tty?.path {
                    HStack {
                        Text("\u{2022} **TTY:**")
                        GroupBox {
                            Text("`\(ttyPath)`")
                                .lineLimit(10)
                        }
                    }
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            
            Divider()
            
            
            GroupBox {
                VStack(alignment: .leading) {
                    Label("**Code signing details**", systemImage: "signature")
                        .font(.title3)
                        .padding([.top, .leading], 5.0)
                    
                    HStack {
                        Text("\u{2022} **Code signing type:**")
                        GroupBox {
                            VStack(alignment: .leading) {
                                Text("`\(codeSigningType)`")
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Process signing ID:**")
                        GroupBox {
                            VStack(alignment: .leading) {
                                Text("`\(signingId)`")
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **`SHA256` Code directory hash:**")
                        GroupBox {
                            Text("`\(cdHash)`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
