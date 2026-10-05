//
//  SystemModifyPasswordMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/23/23.
//

import SwiftUI
import SutroESFramework


/// An `od_modify_password` event's facts: an account's password was changed.
struct SystemOpenDirectoryModifyPasswordMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODModifyPasswordEvent {
        esSystemEvent.event.od_modify_password!
    }
    
    var body: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "the password modification") {
            OpenDirectoryModifyPasswordEventLabelView(message: esSystemEvent)
        } facts: {
            FactRow(name: "Account type", value: event.account_type_string)
            FactRow(name: "Account name", value: event.account_name)
        }
    }
}
