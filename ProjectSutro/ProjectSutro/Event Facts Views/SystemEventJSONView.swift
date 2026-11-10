//
//  SystemEventJSONView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// The event's record, as JSON Export telemetry writes it, colored, with line numbers.
struct SystemEventJSONView: View {
    var selectedMessage: ESMessage
    @State private var jsonText: String = ""

    var body: some View {
        FileContentView(title: "Event JSON", content: jsonText, language: .json)
            .task(id: selectedMessage.objectID) {
                jsonText = IndicatorStore.shared.json(of: selectedMessage)
            }
    }
}
