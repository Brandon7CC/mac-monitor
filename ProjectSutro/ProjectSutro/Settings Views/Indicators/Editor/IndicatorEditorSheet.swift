//
//  IndicatorEditorSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Editing
/// An indicator to add or change: its name, what it means, its symbol and color, how it marks the tables, its severity,
/// its ATT&CK tactic and technique, and its predicate, written as the predicate editor writes one, with what it finds
/// among the events the main window shows, and why the Security Extension can't run it, as it's typed. All but how it
/// marks the tables is the Mac's, and can't be changed while the Mac's indicators can't.
struct IndicatorEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var indicator: Indicator
    @StateObject private var editor = PredicateEditorController()
    /// Are the newest events showing, to start the predicate from one?
    @State private var choosesEvent = false
    /// Did Choose Representative Event find no events?
    @State private var hasNoEvents = false
    /// Is the delete confirmation showing?
    @State private var confirmsDelete = false
    /// The main window's queries, for the preview, or `nil` with no main window.
    let model: EventQueryModel?
    /// May the Mac's indicators be changed? How it marks the tables always may.
    let canChange: Bool
    let save: (Indicator) -> Void
    /// Removes the indicator. `nil` for one that isn't saved yet.
    let delete: ((Indicator) -> Void)?

    /// - Parameters:
    ///   - indicator: The indicator to start from.
    ///   - model: The main window's queries.
    ///   - canChange: May the Mac's indicators be changed?
    ///   - save: Keeps the indicator.
    ///   - delete: Removes it, or `nil` when it's new or can't be.
    init(indicator: Indicator, model: EventQueryModel?, canChange: Bool = true, save: @escaping (Indicator) -> Void,
         delete: ((Indicator) -> Void)? = nil) {
        _indicator = State(initialValue: indicator)
        self.model = model
        self.canChange = canChange
        self.save = save
        self.delete = delete
    }

    var body: some View {
        let problem = indicator.problem
        let sensorProblem = problem == nil ? indicator.sensorProblem : nil
        VStack(spacing: 0) {
            Form {
                if !canChange {
                    Text("This Mac's indicators can't be changed now, so only how the event tables mark this one "
                         + "can.")
                        .foregroundStyle(.secondary)
                }
                Section {
                    TextField("Name", text: $indicator.name, prompt: Text("Reflective loading"))
                    TextField("Description", text: $indicator.description,
                              prompt: Text("Why it's worth a look"), axis: .vertical)
                        .lineLimit(2...4)
                    LabeledContent("Symbol") { SymbolPicker(indicator: $indicator) }
                    colorPicker("Color", selection: $indicator.color)
                    Picker("Severity", selection: $indicator.severity) {
                        ForEach(IndicatorSeverity.allCases.reversed(), id: \.self) { Text($0.name).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .help("How strong a sign of something malicious a match is. Every record that lists it says so.")
                }
                .disabled(!canChange)
                Section {
                    LabeledContent("Event tables") {
                        HStack(spacing: 14) {
                            ForEach(Indicator.TableMarks.each.indices, id: \.self) { position in
                                tableMarkToggle(Indicator.TableMarks.each[position])
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                    .help("How the Unified and Process Execution tables mark its events: the row's dot, its symbol "
                          + "before the event, and the event's type, or an exec's process name, in its color. None "
                          + "leaves its events unmarked, and out of Any indicator, under the Filters button.")
                } footer: {
                    Text("Yours: each user of this Mac chooses how the tables mark it.").foregroundStyle(.secondary)
                }
                Section("MITRE ATT&CK") {
                    TacticPicker(tactic: $indicator.tactic)
                    TextField("Technique", text: Binding { indicator.technique ?? "" } set: { text in
                        let trimmed = text.trimmingCharacters(in: .whitespaces)
                        indicator.technique = trimmed.isEmpty ? nil : trimmed
                    }, prompt: Text("T1543.001"))
                }
                .disabled(!canChange)
                Section {
                    PredicateTextView(text: $indicator.predicate, editor: editor)
                        .frame(height: 140)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
                        .allowsHitTesting(canChange)
                    if let problem {
                        Label(problem, systemImage: "exclamationmark.triangle.fill").font(.caption)
                            .foregroundStyle(.red).textSelection(.enabled)
                    }
                    if let sensorProblem {
                        Label("Not run by the Security Extension: \(sensorProblem)",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                    }
                    Button("Choose Representative Event…") {
                        if RepresentativeEvent.anyRecorded { choosesEvent = true } else { hasNoEvents = true }
                    }
                    .disabled(!canChange)
                } header: {
                    Text("Predicate")
                } footer: {
                    Text("Matched on each event's record, one event at a time. Tab completes a key.")
                        .foregroundStyle(.secondary)
                }
                Section("Preview") {
                    IndicatorPreview(predicate: indicator.predicate, isUsable: problem == nil, model: model)
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
                    save(indicator)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil || indicator.name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(.horizontal, 20).padding(.vertical, 12)
        }
        .confirmationDialog("Delete \(indicator.name)?", isPresented: $confirmsDelete) {
            Button("Delete", role: .destructive) {
                delete?(indicator)
                dismiss()
            }
        } message: {
            Text("Restore Defaults brings back Mac Monitor's own indicators.")
        }
        .frame(width: 560)
        .frame(minHeight: 520, idealHeight: 760, maxHeight: 860)
        .sheet(isPresented: $choosesEvent) {
            let written = !indicator.predicate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            RepresentativeEventSheet(replacesPredicate: written) { indicator.predicate = $0 }
        }
        .alert("No events are recorded", isPresented: $hasNoEvents) {
            Button("OK") {}
        } message: {
            Text("Record some events or open a trace, then choose one to start the predicate from.")
        }
    }

    /// - Parameter each: A table mark, its name and its title (``Indicator/TableMarks/each``).
    /// - Returns: Its checkbox, which marks the tables with it, or not, leaving the others as they are.
    private func tableMarkToggle(_ each: (mark: Indicator.TableMarks, name: String, title: String)) -> some View {
        Toggle(each.title, isOn: Binding {
            indicator.tableMarks.contains(each.mark)
        } set: { isOn in
            if isOn { indicator.tableMarks.insert(each.mark) } else { indicator.tableMarks.remove(each.mark) }
        })
    }

    /// - Parameters:
    ///   - title: What the menu is called.
    ///   - selection: The color it sets.
    /// - Returns: A menu of the colors.
    private func colorPicker(_ title: String, selection: Binding<Indicator.Color>) -> some View {
        Picker(title, selection: selection) {
            ForEach(Indicator.Color.allCases, id: \.self) { color in
                Text(color.rawValue.capitalized).tag(color)
            }
        }
    }
}


/// What an indicator's predicate finds among the events the main window shows, whatever its filters: how many, and the
/// first few, checked again a moment after the predicate stops changing.
private struct IndicatorPreview: View {
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
                preview = try await model.preview(predicate, for: .indicator)
            } catch is CancellationError {
            } catch {
                failure = (error as? CommandLineUsageError)?.message ?? error.localizedDescription
            }
        }
    }
}
