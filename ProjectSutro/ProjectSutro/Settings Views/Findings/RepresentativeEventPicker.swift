//
//  RepresentativeEventPicker.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Representative event
/// A recorded event a finding's predicate can start from, as the sheet lists it.
struct RepresentativeEvent: Identifiable {
    let id: NSManagedObjectID
    let time: String
    let type: String
    /// The initiating process's executable path.
    let process: String
    let target: String
    /// The predicate its key facts make, one clause a line.
    let predicate: String

    /// The record key paths the predicate compares, in order.
    private static let keyPaths = ["es_event_type", "target_path", "process.executable.path", "process.signing_id"]

    /// - Parameter message: The event, on its context's queue.
    init(_ message: ESMessage) {
        id = message.objectID
        time = eventTimeStamp(for: message)
        type = message.es_event_type ?? ""
        process = message.initiating_path ?? ""
        target = message.target_path ?? ""
        let values = [message.es_event_type, message.target_path, message.initiating_path,
                      message.initiating_signing_id]
        predicate = zip(Self.keyPaths, values).compactMap { keyPath, value in
            /// Only key paths the predicate engine knows, which the schema lists.
            guard let value, !value.isEmpty, RecordKeyPaths.shared.nodes[keyPath] != nil else { return nil }
            return "\(keyPath) == \(Self.quoted(value))"
        }.joined(separator: "\nAND ")
    }

    /// - Parameter value: A string.
    /// - Returns: It as a predicate's string literal. Backslashes, quotes and control characters are escaped.
    static func quoted(_ value: String) -> String {
        var literal = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\\": literal += "\\\\"
            case "\"": literal += "\\\""
            case "\n": literal += "\\n"
            case "\r": literal += "\\r"
            case "\t": literal += "\\t"
            case _ where scalar.value < 0x20 || scalar.value == 0x7F:
                literal += String(format: "\\u%04X", scalar.value)
            default: literal.unicodeScalars.append(scalar)
            }
        }
        return literal + "\""
    }

    /// - Parameter limit: How many events.
    /// - Returns: The newest events, newest first. None when the store can't be read.
    static func recent(limit: Int = 500) async -> [RepresentativeEvent] {
        let context = CoreDataController.shared.container.newBackgroundContext()
        return await context.perform {
            let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "mach_time", ascending: false)],
                                            loaded: true)
            request.fetchLimit = limit
            return ((try? context.fetch(request)) ?? []).map(RepresentativeEvent.init)
        }
    }

    /// - Returns: Are any events recorded?
    @MainActor
    static var anyRecorded: Bool {
        ((try? CoreDataController.shared.container.viewContext.count(for: ESMessage.request())) ?? 0) > 0
    }
}


// MARK: - Sheet
/// The newest events, to start a finding's predicate from one. Its search field filters them by type, process and
/// target. Choosing one hands back its predicate, after asking when it would replace one already written.
struct RepresentativeEventSheet: View {
    /// Is a predicate already written, which the chosen one replaces?
    let replacesPredicate: Bool
    let choose: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var events: [RepresentativeEvent]?
    @State private var query = ""
    @State private var selection: NSManagedObjectID?
    /// The chosen event's predicate, while asking to replace the one written.
    @State private var pending: String?

    var body: some View {
        let shown = (events ?? []).filter { event in
            query.isEmpty || [event.type, event.process, event.target].contains {
                $0.localizedCaseInsensitiveContains(query)
            }
        }
        VStack(spacing: 0) {
            HStack {
                Text("Choose Representative Event").font(.headline)
                Spacer()
                TextField("Search", text: $query, prompt: Text("Type, process or path"))
                    .textFieldStyle(.roundedBorder).frame(width: 240)
            }
            .padding(12)
            Table(shown, selection: $selection) {
                TableColumn("Time", value: \.time).width(min: 70, ideal: 90)
                TableColumn("Type") { Text($0.type.droppingPrefix("ES_EVENT_TYPE_NOTIFY_")) }
                    .width(min: 80, ideal: 130)
                TableColumn("Process") { Text($0.process).truncationMode(.middle).help($0.process) }
                TableColumn("Target") { Text($0.target).truncationMode(.middle).help($0.target) }
            }
            .contextMenu(forSelectionType: NSManagedObjectID.self) { _ in } primaryAction: { ids in
                ids.first.map(pick)
            }
            .overlay { if events == nil { ProgressView() } }
            Divider()
            HStack {
                Text("Its type, target path, process path and signing ID, one clause a line.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Choose") { selection.map(pick) }.keyboardShortcut(.defaultAction).disabled(selection == nil)
            }
            .padding(12)
        }
        .frame(width: 760, height: 480)
        .task { events = await RepresentativeEvent.recent() }
        .confirmationDialog("Replace the predicate?", isPresented: Binding { pending != nil } set: { shown in
            if !shown { pending = nil }
        }) {
            Button("Replace", role: .destructive) { pending.map(finish) }
        } message: {
            Text("The predicate written is replaced by the chosen event's.")
        }
    }

    /// - Parameter id: The event chosen.
    private func pick(_ id: NSManagedObjectID) {
        guard let predicate = events?.first(where: { $0.id == id })?.predicate else { return }
        if replacesPredicate { pending = predicate } else { finish(predicate) }
    }

    /// - Parameter predicate: The chosen event's predicate, to hand back.
    private func finish(_ predicate: String) {
        choose(predicate)
        dismiss()
    }
}
