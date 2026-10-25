//
//  SystemOpenDirectoryAttrAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/28/23.
//

import SwiftUI
import SutroESFramework


/// An `od_attribute_value_add` event's facts: a value was added to a record's attribute.
struct SystemOpenDirectoryAttrAddMetadataView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODAttributeValueAddEvent {
        esSystemEvent.event.od_attribute_value_add!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.od_attribute_value_add != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        OpenDirectoryFactsView(message: esSystemEvent, event: event, role: "adding a value to a record") {
            OrangeEventLabelView(message: esSystemEvent)
        } facts: {
            FactRow(name: "Attribute name", value: event.attribute_name)
            FactRow(name: "Attribute value", value: event.attribute_value)
            FactRow(name: "\(event.record_type_string ?? "Record") record name", value: event.record_name)
        }
    }
}
