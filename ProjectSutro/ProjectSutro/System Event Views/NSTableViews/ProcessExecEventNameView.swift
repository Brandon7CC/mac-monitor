//
//  ProcessExecEventNameView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework

struct ProcessExecEventNameView: View {
    var message: ESMessage
    
    private var exec: ESProcessExecEvent {
        message.event.exec!
    }
    
    private var procPath: URL? {
        return URL(string: exec.target.executable?.path ?? "")
    }
    
    private var procName: String {
        if let procPath = procPath {
            return procPath.lastPathComponent
        }
        
        return ""
    }
    
    /// Cached DYLD injection check — avoids calling env.joined().lowercased().contains()
    /// up to 3 times in the view body. This is O(total env string length) and was
    /// previously the most expensive per-row operation in the process exec table.
    private var hasDyldInjection: Bool {
        exec.env
            .joined()
            .lowercased()
            .contains("dyld_insert_libraries")
    }
    
    var body: some View {
        HStack {
            if exec.target.is_adhoc_signed {
                HStack {
                    // @note is the process running as the real root user?
                    if exec.target.ruid == 0 {
                        Image(systemName: "person.crop.circle.badge.exclamationmark.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is running as the root user")
                    } else if exec.target.ruid != exec.target.euid && exec.target.euid == 0 {
                        // @note this process was elevated to root
                        Image(systemName: "key.radiowaves.forward.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process elevated to root!")
                    }
                    
                    if hasDyldInjection {
                        Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette).foregroundStyle(.red)
                    }
                    
                    if exec.target.file_quarantine_type != .disabled {
                        // The process is File Quarantine-aware `LSFileQuarantineEnabled` in `Info.plist`
                        Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is File Quarantine-aware.")
                    }
                    
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .orange).help("Binary is adhoc signed!")
                    Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.orange)
                }.frame(alignment: .leading)
            } else if (exec.target.signing_id ?? "Unknown") == "Unknown" {
                HStack {
                    if exec.target.ruid == 0 {
                        Image(systemName: "person.crop.circle.badge.exclamationmark.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is running as the root user")
                    } else if exec.target.ruid != exec.target.euid && exec.target.euid == 0 {
                        Image(systemName: "key.radiowaves.forward.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process elevated to root!")
                    }
                    
                    if hasDyldInjection {
                        Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette).foregroundStyle(.red)
                    }
                    
                    if exec.target.file_quarantine_type != .disabled {
                        // The process is File Quarantine-aware `LSFileQuarantineEnabled` in `Info.plist`
                        Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is File Quarantine-aware.")
                    }
                    
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .red).help("Unknown signing ID")
                    Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.red)
                }.frame(alignment: .leading)
            } else {
                if exec.target.ruid == 0 {
                    Image(systemName: "person.crop.circle.badge.exclamationmark.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is running as the root user")
                } else if exec.target.ruid != exec.target.euid && exec.target.euid == 0 {
                    Image(systemName: "key.radiowaves.forward.fill").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process elevated to root!")
                }
                
                if hasDyldInjection {
                    Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette).foregroundStyle(.red)
                }
                
                if exec.target.file_quarantine_type != .disabled {
                    // The process is File Quarantine-aware `LSFileQuarantineEnabled` in `Info.plist`
                    Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor).padding([.leading], 2.0).help("Process is File Quarantine-aware.")
                }
                
                Label(procName, systemImage: "checkmark.seal")
            } // root: person.crop.circle.badge.exclamationmark.fill
        }
    }
}
