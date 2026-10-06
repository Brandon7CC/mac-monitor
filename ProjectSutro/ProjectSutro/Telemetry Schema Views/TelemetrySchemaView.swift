//
//  TelemetrySchemaView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Telemetry schema window
/// Help > Telemetry Schema…: Mac Monitor's telemetry schema to read, search, copy and save, and Validate Trace… to
/// check an export against it.
struct TelemetrySchemaView: View {
    /// The schema, and the trace being checked.
    @StateObject private var model: TelemetrySchemaModel
    
    /// What the schema's origin mark means, in Markdown.
    private static let origins: LocalizedStringKey = """
        Every record Mac Monitor exports is eslogger's JSON plus Mac Monitor's additions. Each key's \
        `x-mac-monitor-origin` says which: `eslogger` or `mac-monitor`.
        """
    
    /// - Parameter model: Makes the window's model, once: by default, one for the framework's schema.
    init(model: @autoclosure @escaping () -> TelemetrySchemaModel = TelemetrySchemaModel()) {
        _model = StateObject(wrappedValue: model())
    }
    
    /// The header, then the schema; a trace's check shows in a sheet.
    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            switch model.schema {
            case .success:
                ReadOnlyTextView(text: model.schemaText)
            case .failure(let error):
                unavailable(error)
            }
        }
        .frame(minWidth: 620, minHeight: 360)
        .sheet(isPresented: isChecking) {
            TraceValidationSheet(model: model)
        }
    }
    
    /// Is a trace's check showing? Closing its sheet stops it.
    private var isChecking: Binding<Bool> {
        Binding { model.check != nil } set: { if !$0 { model.close() } }
    }
    
    /// What the schema is, and what to do with it.
    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 16) {
                Text("Mac Monitor telemetry \(TelemetrySchema.version)")
                    .font(.title2.weight(.semibold))
                Spacer(minLength: 0)
                actions
            }
            Text("JSON Schema draft 2020-12 · \(TelemetrySchema.identifier)")
                .foregroundColor(.secondary)
                .textSelection(.enabled)
            Text(Self.origins)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
        }
        .padding()
    }
    
    /// Copy, Save Schema…, and Validate Trace…: off when there's no schema.
    private var actions: some View {
        HStack {
            Button { model.copySchema() } label: { Label("Copy", systemImage: "doc.on.doc") }
                .help("Copy the schema's JSON")
            Button("Save Schema…") { model.saveSchema() }
                .help("Save the schema as \(TelemetrySchema.fileName)")
            Button("Validate Trace…") { model.chooseTrace() }
                .help("Check a Mac Monitor export against the schema")
        }
        .disabled(model.schemaText.isEmpty)
    }
    
    /// Why there's no schema to show.
    ///
    /// - Parameter error: Why the framework couldn't give the schema.
    /// - Returns: The explanation.
    private func unavailable(_ error: Error) -> some View {
        VStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.largeTitle)
                .foregroundColor(.yellow)
            Text("The telemetry schema can't be read.")
                .font(.headline)
            Text(error.localizedDescription)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
