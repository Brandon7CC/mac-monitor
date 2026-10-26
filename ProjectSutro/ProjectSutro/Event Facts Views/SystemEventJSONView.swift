//
//  SystemEventJSONView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemEventJSONView: View {
    var selectedMessage: ESMessage
    @State private var jsonText: String = ""
    
    /// The event's record, as JSON Export telemetry writes it, colored, with line numbers.
    var body: some View {
        FileContentView(title: "Event JSON", content: jsonText, language: .json)
            .task(id: selectedMessage.objectID) {
                jsonText = ProcessHelpers.eventToJSON(value: selectedMessage, pretty: true)
            }
    }
}
