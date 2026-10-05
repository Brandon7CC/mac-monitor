//
//  SystemGroupAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/23.
//

import SwiftUI
import SutroESFramework


/// An `od_group_add` event's facts: a member was added to a group.
struct SystemOpenDirectoryGroupAddMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODGroupAddEvent {
        esSystemEvent.event.od_group_add!
    }
    
    var body: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "adding a member to the group") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            OpenDirectoryGroupMemberFacts(event: event)
        }
    }
}
