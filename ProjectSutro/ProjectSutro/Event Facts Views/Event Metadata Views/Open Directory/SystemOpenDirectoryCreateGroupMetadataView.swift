//
//  SystemOpenDirectoryCreateGroupMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/28/23.
//

import SwiftUI
import SutroESFramework


/// An `od_create_group` event's facts: a group was created.
struct SystemOpenDirectoryCreateGroupMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODCreateGroupEvent {
        esSystemEvent.event.od_create_group!
    }
    
    var body: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "creating the group") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            FactRow(name: "Group name", value: event.group_name)
        }
    }
}
