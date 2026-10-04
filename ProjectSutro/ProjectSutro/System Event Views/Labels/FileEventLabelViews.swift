//
//  FileEventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


struct FileCreateEventLabelView: View {
    var message: ESMessage
    
    private var event: ESFileCreateEvent {
        message.event.create!
    }
    
    var body: some View {
        if let eventType: String = message.es_event_type {
            HStack {
                if (message.process.file_quarantine_type != "DISABLED" || (message.process.executable?.name == "ArchiveService" && !event.targetPath.hasPrefix("/private/var/folders/"))) && event.is_quarantined == 0 {
                    // MARK: Unquarantiened file
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Unquarantined file created")
                    Label("**`\(eventType)`**", systemImage: "doc.plaintext").symbolRenderingMode(.palette).foregroundStyle(.red)
                } else if event.is_quarantined == 1 {
                    // MARK: Quarantined file
                    Image(systemName: "lock.shield").help("File is quarantined")
                    Label("**`\(eventType)`**", systemImage: "doc.plaintext")
                }
                else {
                    Label("**`\(eventType)`**", systemImage: "doc.plaintext")
                }
            }.frame(alignment: .leading)
        }
        
    }
}


struct MMAPEventLabelView: View {
    var message: ESMessage
    
    private var event: ESMMapEvent {
        message.event.mmap!
    }
    
    var body: some View {
        if let eventType: String = message.es_event_type {
            let filePath: String = event.source.path!
            // MARK: MMAP OSA
            if pathIsOSAComponent(filePath: filePath) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("This file is an OSA (Open Scripting Architecture) component")
                    Label("**`\(eventType)`**", systemImage: "memorychip").foregroundStyle(.orange)
                }
            } else {
                Label("**`\(eventType)`**", systemImage: "memorychip")
            }
        }
        
    }
}


struct DeleteXattrEventLabelView: View {
    var message: ESMessage
    
    private var event: ESXattrDeleteEvent {
        message.event.deleteextattr!
    }
    
    var body: some View {
        let xattr = event.extattr
        // MARK: Quarantine Xattr Delete
        if xattr.hasSuffix("apple.quarantine") {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Quarantine extended attribute deleted")
                Label("**`\(message.es_event_type!)`**", systemImage: "lock.slash").symbolRenderingMode(.palette).foregroundStyle(.red)
            }
        } else {
            Label("**`\(message.es_event_type!)`**", systemImage: eventStringToImage(from: message.es_event_type!)).foregroundStyle(.orange)
        }
    }
}


struct SetXattrEventLabelView: View {
    var message: ESMessage
    
    private var event: ESXattrSetEvent {
        message.event.setextattr!
    }
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        if event.extattr == "com.apple.quarantine" {
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).symbolRenderingMode(.palette).foregroundStyle(.green)
        } else {
            Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
        }
    }
}


struct MountEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: "mount")
    }
}


struct FDDuplicateEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: "folder.badge.plus")
    }
}


struct FileRenameEventLabelView: View {
    var message: ESMessage
    private var event: ESFileRenameEvent { message.event.rename! }
    
    var body: some View {
        guard let eventType = message.es_event_type else { return AnyView(EmptyView()) }
        let config = configuration(for: event)
        
        return AnyView(
            HStack {
                if let icon = config.icon {
                    icon
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(config.iconStyle)
                        .help(config.iconHelp)
                }
                Label("**`\(eventType)`**", systemImage: config.labelIcon)
                    .foregroundStyle(config.labelStyle)
            }
        )
    }
    
    private func configuration(for event: ESFileRenameEvent) -> (icon: Image?, iconStyle: Color, iconHelp: String, labelStyle: Color, labelIcon: String) {
        if event.is_quarantined == 1 {
            // MARK: Quarantined inflated file
            return (Image(systemName: "lock.shield"), .primary, "File is quarantined", .primary, "filemenu.and.cursorarrow")
        } else if event.is_quarantined == 0 && event.destination_path.hasSuffix(".app") {
            // MARK: Unquarantined app bundle
            return (Image(systemName: "hand.raised.app"), .red, "Unquarantined application bundle", .red, "filemenu.and.cursorarrow")
        } else if event.destination_path.contains("com.apple.backgroundtaskmanagement") {
            // MARK: BTM modification
            return (Image(systemName: "exclamationmark.triangle.fill"), .yellow, "Service management database modified.", .orange, "lock.doc")
        } else {
            return (nil, .primary, "", .primary, "filemenu.and.cursorarrow")
        }
    }
}


struct FileDeleteEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: eventStringToImage(from: message.es_event_type!))
    }
}


struct FileOpenEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: eventStringToImage(from: message.es_event_type!))
    }
}


struct FileWriteEventLabelView: View {
    var message: ESMessage
    
    private var event: ESFileWriteEvent {
        message.event.write!
    }
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            if let path = event.target.path,
               path.contains("backgroundtaskmanagementd") {
                // MARK: Login Item
                Image(systemName: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .yellow)
                    .help("A Login Item was potentially added")
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
                    .foregroundStyle(.orange)
            } else {
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            }
        }
        
    }
}


struct FileLinkEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct FileCloseEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct IOKitOpenEventLabelView: View {
    var message: ESMessage
    
    private var event: ESIOKitOpenEvent {
        message.event.iokit_open!
    }
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        HStack {
            // MARK: HID Device
            if event.user_client_class.contains("IOHIDLibUserClient") {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("Human Interface Device (HID) attached!")
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType)).foregroundStyle(.orange)
            } else {
                Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            }
        }
    }
}
