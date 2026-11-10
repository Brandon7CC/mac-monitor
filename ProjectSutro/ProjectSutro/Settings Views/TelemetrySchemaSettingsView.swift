//
//  TelemetrySchemaSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > Telemetry Schema
/// Settings > Telemetry Schema: the schema's version, to show, copy or save, and a trace to check against it, here or
/// from a terminal. Help > Telemetry Schema opens the same window Show does.
struct TelemetrySchemaSettingsView: View {
    @Environment(\.openWindow) private var openWindow
    @StateObject private var model = TelemetrySchemaModel()

    /// The command that checks a trace from a terminal.
    private static let validateCommand = "macmonitor validate trace.jsonl"

    var body: some View {
        SettingsForm(pane: .telemetrySchema) {
            Section {
                LabeledContent {
                    HStack {
                        Button("Show…") { openWindow(id: ProjectSutroApp.schemaWindow) }
                        Button("Copy") { model.copySchema() }
                        Button("Save…") { model.saveSchema() }
                    }
                    .disabled(model.schemaText.isEmpty)
                } label: {
                    SettingsIconLabel("Telemetry \(TelemetrySchema.version)", detail: "JSON Schema draft 2020-12",
                                      symbol: "doc.text.magnifyingglass", tint: .indigo)
                }
                LabeledContent {
                    HStack {
                        SettingsCopyButton(text: Self.validateCommand, what: "the command")
                        Button("Validate Trace…") { model.chooseTrace() }
                            .disabled(model.schemaText.isEmpty)
                    }
                } label: {
                    SettingsIconLabel("Validate a trace", detail: Self.validateCommand,
                                      symbol: "checkmark.seal.fill", tint: .green)
                }
            }
        }
        .sheet(isPresented: Binding { model.check != nil } set: { if !$0 { model.close() } }) {
            TraceValidationSheet(model: model)
        }
    }
}
