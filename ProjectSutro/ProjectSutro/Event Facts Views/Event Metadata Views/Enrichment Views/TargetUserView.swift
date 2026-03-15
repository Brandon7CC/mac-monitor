//
//  TargetUserView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

// MARK: Target user
struct TargetUserView: View {
    var selectedMessage: ESMessage
    
    private var exec: ESProcessExecEvent? {
        selectedMessage.event.exec
    }
    
    private var fork: ESProcessForkEvent? {
        selectedMessage.event.fork
    }
    
    private var ruid: Int {
        if let exec = exec {
            return exec.target.ruid ?? 0
        } else if let fork = fork {
            return fork.child.ruid ?? 0
        }

        return selectedMessage.process.ruid ?? 0
    }
    
    private var ruid_human: String {
        if let exec = exec {
            return exec.target.ruid_human ?? ""
        } else if let fork = fork {
            return fork.child.ruid_human ?? ""
        }
        
        return selectedMessage.process.ruid_human ?? ""
    }
    
    private var euid: Int {
        if let exec = exec {
            return exec.target.euid ?? 0
        } else if let fork = fork {
            return fork.child.euid ?? 0
        }

        return selectedMessage.process.euid ?? 0
    }
    
    private var euid_human: String {
        if let exec = exec {
            return exec.target.euid_human ?? ""
        } else if let fork = fork {
            return fork.child.euid_human ?? ""
        }
        
        return selectedMessage.process.euid_human ?? ""
    }
    
    var body: some View {
        if ruid != euid {
            HStack {
                Text("**Real:**")
//                    .font(.title3)
                GroupBox {
                    Text("`\(ruid_human) (\(ruid))`")
//                        .font(.title3)
                }
                Image(systemName: "arrow.right")
                Text("**Effective:**")
//                    .font(.title3)
                GroupBox {
                    Text("`\(euid_human) (\(euid))`")
//                        .font(.title3)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        } else {
            HStack {
                GroupBox {
                    Text("`\(euid_human) (\(euid))`")
//                        .font(.title3)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
