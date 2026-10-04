//
//  ProcessEventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


struct ExecEventLabelView: View {
    var message: ESMessage
    
    private var event: ESProcessExecEvent {
        message.event.exec!
    }
    
    private var procPath: String {
        event.target.executable?.path ?? ""
    }
    
    var body: some View {
        HStack {
            // MARK: Dyld Exec Path
            if event.dyld_exec_path != nil && event.dyld_exec_path != procPath {
                Image(systemName: "curlybraces.square").help("Dyld exec path does not match the process path.")
            }
            
            // MARK: DYLD_INSERT_LIBRARIES
            if event.env
                .joined().lowercased()
                .contains("dyld_insert_libraries") {
                Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
            
            // MARK: File Quarantine-aware
            if event.target.file_quarantine_type != "DISABLED" {
                Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor)
                    .padding([.leading], 2.0)
                    .help("Target is File Quarantine-aware.")
            }
            
            // MARK: ADHOC
            if event.target.is_adhoc_signed {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                Label("**`\(message.es_event_type!)`**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.orange)
            } else if event.target.signing_id != nil && event.target.signing_id! != "Unknown" {
                // MARK: Signed
                Label("**`\(message.es_event_type!)`**", systemImage: "checkmark.seal")
            } else {
                // MARK: Unsigned
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .red)
                Label("**`\(message.es_event_type!)`**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
        }.frame(alignment: .leading)
    }
}


struct ForkEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        if let eventType: String = message.es_event_type {
            Label(
                "**`\(eventType)`**",
                systemImage: "point.topleft.down.curvedto.point.bottomright.up"
            )
        }
    }
}


struct ExitEventLabelView: View {
    var message: ESMessage
    
    private var event: ESProcessExitEvent {
        message.event.exit!
    }
    
    var body: some View {
        HStack {
            // MARK: Non-zero Exit Code
            if event.stat != 0 {
                Image(systemName: "info.square").symbolRenderingMode(.palette).help("Non-zero exit code")
            }
            Label("**`\(message.es_event_type!)`**", systemImage: "eject.fill")
        }
    }
}


struct RemoteThreadCreateEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Remote thread created!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.red)
        }
    }
}


struct CodeSignatureInvalidatedEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("This process has its code signature invalidated!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.red)
        }
    }
}


struct ProcessSocketEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct ProcessTraceEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Process trace occuring")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.orange)
        }
    }
}


struct GetTaskEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Retrieving task control port!")
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.orange)
        }
    }
}


struct ProcessCheckEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct ProcessSignalEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}
