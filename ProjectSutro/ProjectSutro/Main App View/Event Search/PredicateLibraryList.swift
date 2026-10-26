//
//  PredicateLibraryList.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI


/// One search of what can go in a predicate: related events, saved and recent predicates, and the record's key paths
/// by group, each badged as the completion list badges it. Lazy, and drawn again only when its search or what it
/// lists changes, not as the predicate is typed.
struct PredicateLibraryList: View, Equatable {
    let query: String
    let saved: [EventSearchController.SavedPredicate]
    let recents: [String]
    let editor: PredicateEditorController
    /// Puts a predicate in the editor.
    let load: (String) -> Void
    let delete: (EventSearchController.SavedPredicate) -> Void

    /// The sections shown open without a search.
    @State private var expanded: Set<String> = [RecordKeyLibrary.relatedTitle, Self.savedTitle, "Record", "Process"]
    /// The sections closed during a search, which opens every one that matches: open again when the search changes.
    @State private var closedInSearch: Set<String> = []

    private static let savedTitle = "Saved", recentTitle = "Recent"

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.query == rhs.query && lhs.saved == rhs.saved && lhs.recents == rhs.recents
    }

    /// A row: what it is, its name, what it is under it, its type, and what clicking it does.
    struct Item: Identifiable {
        let id: String
        let badge: CompletionBadge.Kind
        let name: String
        var detail: String?
        var type = ""
        var help: String?
        let action: () -> Void
    }

    var body: some View {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        let sections = self.sections.compactMap { title, items -> (String, [Item])? in
            let items = query.isEmpty ? items : items.filter {
                $0.name.lowercased().contains(query) || $0.detail?.lowercased().contains(query) == true
            }
            return items.isEmpty ? nil : (title, items)
        }
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: .sectionHeaders) {
                ForEach(sections, id: \.0) { title, items in
                    let isOpen = query.isEmpty ? expanded.contains(title) : !closedInSearch.contains(title)
                    Section {
                        if isOpen {
                            ForEach(items.prefix(400)) { item in
                                Button(action: item.action) { LibraryRow(item: item) }
                                    .buttonStyle(.plain)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 3)
                                    .contextMenu {
                                        if let predicate = saved.first(where: { "saved:\($0.id)" == item.id }) {
                                            Button("Delete", role: .destructive) { delete(predicate) }
                                        }
                                    }
                            }
                        }
                    } header: {
                        header(title, count: items.count, isOpen: isOpen, searching: !query.isEmpty)
                    }
                }
            }
        }
        .overlay {
            if sections.isEmpty { Text("Nothing matches “\(query)”.").foregroundStyle(.secondary) }
        }
        .onChange(of: query) { _ in closedInSearch = [] }
    }

    /// Related events, Saved, Recent, then the record's keys by group.
    private var sections: [(String, [Item])] {
        let key = { (key: RecordKeyLibrary.Key) in
            Item(id: key.path, badge: key.type == "related" ? .related : .key, name: key.path, detail: key.detail,
                 type: key.type == "related" ? "" : key.type, help: key.summary) {
                editor.insert(key.insertion ?? key.path)
            }
        }
        let saved = saved.map { saved in
            Item(id: "saved:\(saved.id)", badge: .saved, name: saved.name,
                 detail: EventSearchController.oneLine(saved.source), help: saved.source) { load(saved.source) }
        }
        let recents = recents.map { source in
            Item(id: "recent:\(source)", badge: .recent, name: EventSearchController.oneLine(source), help: source) {
                load(source)
            }
        }
        let groups = RecordKeyLibrary.groups.map { ($0.title, $0.keys.map(key)) }
        return [groups[0], (Self.savedTitle, saved), (Self.recentTitle, recents)] + groups.dropFirst()
    }

    /// - Parameters:
    ///   - title: The section's title.
    ///   - count: How many rows it has.
    ///   - isOpen: Is it open?
    ///   - searching: Is a search showing every section that matches open?
    /// - Returns: Its header, which opens and closes it, with a search or without.
    private func header(_ title: String, count: Int, isOpen: Bool, searching: Bool) -> some View {
        Button {
            if searching {
                closedInSearch.formSymmetricDifference([title])
            } else {
                expanded.formSymmetricDifference([title])
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "chevron.right").font(.caption2.weight(.semibold))
                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                Text(title)
                Spacer()
                Text("\(count)").monospacedDigit()
            }
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(.bar)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title), \(count) \(isOpen ? "open" : "closed")")
    }
}

/// One row of the library: its badge, its name and what it is, and its type.
private struct LibraryRow: View {
    let item: PredicateLibraryList.Item

    var body: some View {
        HStack(spacing: 8) {
            CompletionBadge(item.badge)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name)
                    .font(item.badge == .saved ? .callout : .system(size: 11.5, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                if let detail = item.detail {
                    Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            Text(item.type).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(minHeight: 20)
        .contentShape(Rectangle())
        .help(item.help ?? "")
    }
}
