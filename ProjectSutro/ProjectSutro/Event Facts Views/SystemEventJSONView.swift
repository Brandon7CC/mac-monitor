//
//  SystemEventJSONView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// The event's record, as JSON Export telemetry writes it, colored, with line numbers. It's made again when the
/// indicators change, since the record lists the event's indicators.
struct SystemEventJSONView: View {
    var selectedMessage: ESMessage
    @ObservedObject private var indicatorStore = IndicatorStore.shared
    @State private var jsonText: String = ""

    var body: some View {
        FileContentView(title: "Event JSON", content: jsonText, language: .json)
            .task(id: "\(selectedMessage.objectID)|\(indicatorStore.revision)") {
                jsonText = indicatorStore.json(of: selectedMessage)
            }
    }
}
