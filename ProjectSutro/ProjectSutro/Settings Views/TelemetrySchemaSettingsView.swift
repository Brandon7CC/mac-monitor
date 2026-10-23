//
//  TelemetrySchemaSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Telemetry Schema
/// Settings ▸ Telemetry Schema: which schema Mac Monitor's records follow, the schema to read, copy or save, and a
/// trace to check against it. Help ▸ Telemetry Schema… opens the same window Show… does.
struct TelemetrySchemaSettingsView: View {
    @Environment(\.openWindow) private var openWindow
    @StateObject private var model = TelemetrySchemaModel()

    /// The command that checks a trace from a terminal.
    private static let validateCommand = "macmonitor validate trace.jsonl"

    var body: some View {
        SettingsForm(pane: .telemetrySchema) {
            Section {
                LabeledContent { Text(TelemetrySchema.version) } label: {
                    SettingsIconLabel("Version", symbol: "tag.fill", tint: .purple)
                }
                LabeledContent { Text(TelemetrySchema.identifier).monospaced().textSelection(.enabled) } label: {
                    SettingsIconLabel("Identifier", symbol: "number", tint: .gray)
                }
                LabeledContent { Text("JSON Schema draft 2020-12") } label: {
                    SettingsIconLabel("Standard", symbol: "curlybraces", tint: .blue)
                }
                LabeledContent { Text(TelemetrySchema.versionKey).monospaced() } label: {
                    SettingsIconLabel("Each record carries it as", symbol: "key.fill", tint: .orange)
                }
            } footer: {
                Text("Each key's x-mac-monitor-origin says whose it is: eslogger or mac-monitor.")
                    .foregroundStyle(.secondary)
            }
            Section {
                LabeledContent {
                    Button("Show…") { openWindow(id: ProjectSutroApp.schemaWindow) }
                } label: {
                    SettingsIconLabel("Show the schema", detail: "Read and search it in its own window.",
                                      symbol: "doc.text.magnifyingglass", tint: .indigo)
                }
                LabeledContent {
                    Button("Copy") { model.copySchema() }
                } label: {
                    SettingsIconLabel("Copy the schema", detail: "Its JSON, to paste into another validator.",
                                      symbol: "doc.on.doc", tint: .gray)
                }
                LabeledContent {
                    Button("Save…") { model.saveSchema() }
                } label: {
                    SettingsIconLabel("Save the schema", detail: "As \(TelemetrySchema.fileName).",
                                      symbol: "square.and.arrow.down", tint: .blue)
                }
            } header: {
                Text("The schema")
            } footer: {
                Text("Each release also attaches it as \(TelemetrySchema.releaseAssetName).")
                    .foregroundStyle(.secondary)
            }
            .disabled(model.schemaText.isEmpty)
            Section("Check a trace") {
                LabeledContent {
                    Button("Validate Trace…") { model.chooseTrace() }
                } label: {
                    SettingsIconLabel("Validate a trace",
                                      detail: "Checks a JSONL or pretty JSON export, record by record.",
                                      symbol: "checkmark.seal.fill", tint: .green)
                }
                .disabled(model.schemaText.isEmpty)
                LabeledContent {
                    SettingsCopyButton(text: Self.validateCommand, what: "the command")
                } label: {
                    HStack(spacing: 10) {
                        SettingsRowIcon("terminal.fill", Color(white: 0.22))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("From a terminal")
                            Text(Self.validateCommand).font(.caption.monospaced()).foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
        }
        .sheet(isPresented: Binding { model.check != nil } set: { if !$0 { model.close() } }) {
            TraceValidationSheet(model: model)
        }
    }
}
