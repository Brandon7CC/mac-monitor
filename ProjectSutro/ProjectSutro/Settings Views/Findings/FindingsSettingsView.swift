//
//  FindingsSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Indicators
/// Settings ▸ Indicators: what Event Facts points out, each a predicate on an event's record, as a card in
/// Correlation (among the events of the process an exec created) or Groups (among a group's execs). Mac Monitor's own
/// are there to start, to change, turn off, or restore.
struct FindingsSettingsView: View {
    @ObservedObject private var store = FindingStore.shared
    /// The main window's search, whose queries preview what a finding finds.
    @EnvironmentObject private var search: EventSearchController
    /// The finding being edited, or a new one.
    @State private var editing: Finding?
    @State private var confirmsRestore = false

    var body: some View {
        SettingsForm(pane: .findings) {
            Section {
                HStack(spacing: 10) {
                    Text("\(store.findings.filter(\.isEnabled).count) of \(store.findings.count) on")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Restore Defaults…") { confirmsRestore = true }
                        .disabled(store.isDefault)
                    Button("Add Indicator…") { editing = Self.newFinding }
                }
            } footer: {
                Text("An indicator's predicate compares one event's record, as macmonitor stream --predicate does. "
                     + "Settings ▸ Telemetry Schema describes every key.")
                    .foregroundStyle(.secondary)
            }
            Section("Indicators") {
                ForEach(store.findings) { finding in
                    FindingRow(finding: finding, isOn: Binding { finding.isEnabled } set: { on in
                        var changed = finding
                        changed.isEnabled = on
                        store.save(changed)
                    }) { editing = finding }
                    .contextMenu {
                        Button("Edit…") { editing = finding }
                        Button("Duplicate") {
                            var copy = finding
                            copy.id = UUID()
                            copy.name += " copy"
                            store.save(copy)
                        }
                        Divider()
                        Button("Delete", role: .destructive) { store.delete(finding) }
                    }
                }
            }
        }
        .sheet(item: $editing) { finding in
            FindingEditorSheet(finding: finding, model: search.queries, save: { store.save($0) },
                               delete: store.findings.contains { $0.id == finding.id } ? { store.delete($0) } : nil)
        }
        .confirmationDialog("Restore Mac Monitor's indicators?", isPresented: $confirmsRestore) {
            Button("Restore Defaults", role: .destructive) { store.restoreDefaults() }
        } message: {
            Text("Indicators you added or changed are removed.")
        }
    }

    /// What Add Indicator starts from.
    private static var newFinding: Finding {
        Finding(name: "", explanation: "", symbol: "exclamationmark.magnifyingglass", color: .orange,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#, correlation: true, groups: false)
    }
}


/// One finding: its symbol and name, where it shows, its predicate, and its switch.
private struct FindingRow: View {
    let finding: Finding
    @Binding var isOn: Bool
    let edit: () -> Void

    var body: some View {
        LabeledContent {
            HStack(spacing: 10) {
                Button("Edit…", action: edit)
                Toggle("Look for \(finding.name)", isOn: $isOn).labelsHidden().toggleStyle(.switch)
            }
        } label: {
            HStack(spacing: 10) {
                SettingsRowIcon(finding.symbol, finding.tint)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(finding.name)
                        if finding.showsInCorrelation { tag("Correlation") }
                        if finding.showsInGroups { tag("Groups") }
                        if finding.showsInTables { tag("Tables") }
                        if finding.problem != nil {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                                .help("Its predicate can't be used, so it's never found.")
                        }
                    }
                    Text(finding.predicate).font(.caption.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail).help(finding.predicate)
                }
            }
        }
    }

    /// - Parameter title: Where it shows.
    /// - Returns: A small tag.
    private func tag(_ title: String) -> some View {
        Text(title).font(.caption2.weight(.medium)).foregroundStyle(.secondary)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
    }
}


// MARK: - Editing
/// A finding to add or change: its name, what it means, its symbol and color, where it shows, and its predicate,
/// written as the predicate editor writes one, with what it finds among the events the main window shows.
struct FindingEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var finding: Finding
    @StateObject private var editor = PredicateEditorController()
    /// Are the newest events showing, to start the predicate from one?
    @State private var choosesEvent = false
    /// Did Choose Representative Event find no events?
    @State private var hasNoEvents = false
    /// Is the delete confirmation showing?
    @State private var confirmsDelete = false
    /// The main window's queries, for the preview, or `nil` with no main window.
    let model: EventQueryModel?
    let save: (Finding) -> Void
    /// Removes the finding. `nil` for one that isn't saved yet.
    let delete: ((Finding) -> Void)?

    /// - Parameters:
    ///   - finding: The finding to start from.
    ///   - model: The main window's queries.
    ///   - save: Keeps the finding.
    ///   - delete: Removes it, or `nil` when it's new.
    init(finding: Finding, model: EventQueryModel?, save: @escaping (Finding) -> Void,
         delete: ((Finding) -> Void)? = nil) {
        _finding = State(initialValue: finding)
        self.model = model
        self.save = save
        self.delete = delete
    }

    var body: some View {
        let problem = finding.problem
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $finding.name, prompt: Text("Reflective loading"))
                    TextField("Explanation", text: $finding.explanation,
                              prompt: Text("Why it's worth a look"), axis: .vertical)
                        .lineLimit(2...4)
                    LabeledContent("Symbol") { SymbolPicker(finding: $finding) }
                    colorPicker("Color", selection: $finding.color)
                    Picker("Rendering", selection: $finding.rendering) {
                        ForEach(Finding.Rendering.allCases, id: \.self) { rendering in
                            Text(rendering.rawValue.capitalized).tag(rendering)
                        }
                    }
                    if finding.rendering == .palette {
                        colorPicker("First layer", selection: layer(0))
                        colorPicker("Second layer", selection: layer(1))
                    }
                    Toggle("Show in Correlation", isOn: $finding.showsInCorrelation)
                    Toggle("Show in Groups", isOn: $finding.showsInGroups)
                    Toggle("Event tables and Filters", isOn: $finding.showsInTables)
                        .help("Mark its events in the Unified and Process Execution tables, and offer it under the "
                              + "Filters button")
                }
                Section {
                    PredicateTextView(text: $finding.predicate, editor: editor)
                        .frame(height: 140)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
                    if let problem {
                        Label(problem, systemImage: "exclamationmark.triangle.fill").font(.caption)
                            .foregroundStyle(.red).textSelection(.enabled)
                    }
                    Button("Choose Representative Event…") {
                        if RepresentativeEvent.anyRecorded { choosesEvent = true } else { hasNoEvents = true }
                    }
                } header: {
                    Text("Predicate")
                } footer: {
                    Text("Matched on each event's record, one event at a time. Tab completes a key.")
                        .foregroundStyle(.secondary)
                }
                Section("Preview") {
                    FindingPreview(predicate: finding.predicate, isUsable: problem == nil, model: model)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                if delete != nil {
                    Button("Delete Indicator…", role: .destructive) { confirmsDelete = true }
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    save(finding)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil || finding.name.trimmingCharacters(in: .whitespaces).isEmpty
                          || !(finding.showsInCorrelation || finding.showsInGroups || finding.showsInTables))
            }
            .padding(.horizontal, 20).padding(.vertical, 12)
        }
        .confirmationDialog("Delete \(finding.name)?", isPresented: $confirmsDelete) {
            Button("Delete", role: .destructive) {
                delete?(finding)
                dismiss()
            }
        } message: {
            Text("Restore Defaults brings back Mac Monitor's own indicators.")
        }
        .frame(width: 560)
        .frame(minHeight: 520, idealHeight: 760, maxHeight: 860)
        .sheet(isPresented: $choosesEvent) {
            let written = !finding.predicate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            RepresentativeEventSheet(replacesPredicate: written) { finding.predicate = $0 }
        }
        .alert("No events are recorded", isPresented: $hasNoEvents) {
            Button("OK") {}
        } message: {
            Text("Record some events or open a trace, then choose one to start the predicate from.")
        }
    }

    /// - Parameters:
    ///   - title: What the menu is called.
    ///   - selection: The color it sets.
    /// - Returns: A menu of the colors.
    private func colorPicker(_ title: String, selection: Binding<Finding.Color>) -> some View {
        Picker(title, selection: selection) {
            ForEach(Finding.Color.allCases, id: \.self) { color in
                Text(color.rawValue.capitalized).tag(color)
            }
        }
    }

    /// - Parameter layer: A layer of the symbol's palette.
    /// - Returns: Its color. A layer without one takes the finding's color.
    private func layer(_ layer: Int) -> Binding<Finding.Color> {
        Binding {
            finding.palette.indices.contains(layer) ? finding.palette[layer] : finding.color
        } set: { color in
            while finding.palette.count <= layer { finding.palette.append(finding.color) }
            finding.palette[layer] = color
        }
    }
}


/// What a finding's predicate finds among the events the main window shows, whatever its filters: how many, and the
/// first few, checked again a moment after the predicate stops changing.
private struct FindingPreview: View {
    let predicate: String
    /// Can the predicate be used?
    let isUsable: Bool
    let model: EventQueryModel?

    @State private var preview: EventQueryModel.Preview?
    @State private var failure: String?

    var body: some View {
        Group {
            if model == nil {
                Text("Open Mac Monitor's main window to see what it finds.").foregroundStyle(.secondary)
            } else if !isUsable {
                Text("Fix the predicate to see what it finds.").foregroundStyle(.secondary)
            } else if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            } else if let preview {
                LabeledContent("Matches") {
                    Text("\(preview.matched.formatted()) of \(preview.total.formatted()) events")
                        .monospacedDigit()
                }
                ForEach(preview.examples) { example in
                    HStack(spacing: 10) {
                        Text(example.time).monospacedDigit().foregroundStyle(.secondary)
                        Text(example.type.droppingPrefix("ES_EVENT_TYPE_NOTIFY_"))
                            .fontWeight(.medium)
                        Text(example.context).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                            .help(example.context)
                    }
                    .font(.caption.monospaced())
                }
                if preview.unchecked > 0 {
                    Text("\(preview.unchecked.formatted()) couldn't be checked.").font(.caption)
                        .foregroundStyle(.orange)
                }
            } else {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Checking every event…").foregroundStyle(.secondary)
                }
            }
        }
        .task(id: "\(isUsable)\(predicate)") {
            preview = nil
            failure = nil
            guard isUsable, let model else { return }
            /// Not on every keystroke.
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard !Task.isCancelled else { return }
            do {
                preview = try await model.preview(predicate, for: .finding)
            } catch is CancellationError {
            } catch {
                failure = (error as? CommandLineUsageError)?.message ?? error.localizedDescription
            }
        }
    }
}
