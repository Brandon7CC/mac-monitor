//
//  SystemEventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


struct BTMLaunchItemAddEventLabelView: View {
    var message: ESMessage
    
    private var event: ESLaunchItemAddEvent {
        message.event.btm_launch_item_add!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("These events indicate a background task was added")
            Label("**`\(message.es_event_type!)`**", systemImage: "lock.doc").symbolRenderingMode(.palette).foregroundStyle(.orange)
        }.frame(alignment: .leading)
    }
}


struct BTMLaunchItemRemoveEventLabelView: View {
    var message: ESMessage
    
    private var event: ESLaunchItemRemoveEvent {
        message.event.btm_launch_item_remove!
    }
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow).help("These events indicate a background task was removed")
            Label("**`\(message.es_event_type!)`**", systemImage: "lock.doc").symbolRenderingMode(.palette).foregroundStyle(.orange)
        }.frame(alignment: .leading)
    }
}


struct OpenSSHLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Label("**`\(message.es_event_type!)`**", systemImage: "network").symbolRenderingMode(.palette).foregroundStyle(.blue)
        }.frame(alignment: .leading)
    }
}


struct XProtectMalwareDetectedEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .purple)
            Label("**`\(message.es_event_type!)`**", systemImage: "bolt.shield").symbolRenderingMode(.palette).foregroundStyle(.purple)
        }.frame(alignment: .leading)
    }
}


struct XProtectMalwareRemediatedEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .purple)
            Label("**`\(message.es_event_type!)`**", systemImage: "checkmark.shield").symbolRenderingMode(.palette).foregroundStyle(.purple)
        }.frame(alignment: .leading)
    }
}


struct LoginLoginEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: "person.fill.checkmark").foregroundStyle(.blue)
    }
}


struct LoginWindowLoginEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: "macwindow.badge.plus").foregroundStyle(.blue)
    }
}


struct LoginWindowUnlockEventLabelView: View {
    var message: ESMessage
    
    var body: some View {
        Label("**`\(message.es_event_type!)`**", systemImage: "macwindow.badge.plus").foregroundStyle(.blue)
    }
}


struct ProfileAddEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
    }
}


struct OpenDirectoryCreateUserEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette).foregroundStyle(.orange)
            .help("A user was added to an Open Directory node.")
    }
}


struct OpenDirectoryModifyPasswordEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette).foregroundStyle(.orange)
            .help("A user's password was modified in an Open Directory node.")
    }
}


struct OrangeEventLabelView: View {
    var message: ESMessage
    
    private var eventType: String {
        message.es_event_type!
    }
    
    var body: some View {
        Label("**`\(eventType)`**", systemImage: eventStringToImage(from: eventType))
            .symbolRenderingMode(.palette)
            .foregroundStyle(.orange)
    }
}
