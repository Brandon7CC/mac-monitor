//
//  XProtectRulesSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/26/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > XProtect Rules
/// Settings > XProtect Rules: the YARA rules Mac Monitor scans files and scripts with, from the XProtect bundle the
/// Security Extension scans with. A sortable table lists them, filtered by rule file or report-only and searched by
/// name, identifier or UUID. Selecting a rule shows it in the inspector beside the table, with its source. The
/// header says whether the Security Extension has the rules compiled and loaded, and a rule file that didn't load
/// says why under it. Event Facts' XProtect scan opens it at a rule that matched (``XProtectRuleReveal``).
struct XProtectRulesSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    /// This Mac's rules, once they're read.
    @State private var catalog: XProtectRuleCatalog?
    /// Whether the Security Extension has them loaded, or `nil` until it says, or when it can't.
    @State private var status: XProtectRuleStatus?
    @State private var isReading = true
    @State private var filter = Filter.all
    @State private var query = ""
    @State private var sortOrder = [KeyPathComparator(\XProtectRule.name)]
    @State private var selection: XProtectRule.ID?
    /// The rules the table shows. They're filtered and sorted again only when the filter, search or order changes.
    @State private var rows: [XProtectRule] = []
    /// The rule Event Facts asked to show.
    @ObservedObject private var reveal = XProtectRuleReveal.shared

    /// Which rules the table shows.
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", files = "Files", scripts = "Scripts", reportOnly = "Report-only"
        var id: String { rawValue }

        /// Does the filter keep a rule?
        ///
        /// - Parameter rule: The rule.
        /// - Returns: `true` when the table shows it.
        func keeps(_ rule: XProtectRule) -> Bool {
            switch self {
            case .all: true
            case .files: rule.file == .xprotect
            case .scripts: rule.file == .scripts
            case .reportOnly: rule.isReportOnly
            }
        }
    }

    var body: some View {
        SettingsPage(pane: .xprotectRules, detail: detail) {
            ForEach(status?.problems ?? [], id: \.self) { problem in
                Label(problem, systemImage: "exclamationmark.triangle.fill").symbolRenderingMode(.multicolor)
            }
            HStack(spacing: 10) {
                Picker("Show", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
                SettingsSearchField(text: $query, prompt: "Search rules")
            }
            HStack(spacing: 0) {
                table
                Divider()
                XProtectRuleInspector(rule: catalog?.rules.first { $0.id == selection })
                    .frame(minWidth: 240, idealWidth: 320, maxWidth: 320)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .layoutPriority(1)
            }
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(.separator))
        }
        .task {
            catalog = await Task.detached(priority: .userInitiated) { XProtectRuleCatalog.read() }.value
            isReading = false
            rows = matches
            takeReveal()
        }
        .onChange(of: filter) { _ in rows = matches }
        .onChange(of: query) { _ in rows = matches }
        .onChange(of: sortOrder) { _ in rows = matches }
        .onChange(of: reveal.identifier) { _ in takeReveal() }
        .onAppear { systemExtensionManager.xprotectRuleStatus { status = $0 } }
    }

    /// Show the rule Event Facts asked for, once the rules are read: every rule file, searched for by the rule's
    /// identifier, and the rule selected so the inspector shows it. A rule this Mac's XProtect doesn't have leaves
    /// the search, which then says no rules match.
    private func takeReveal() {
        guard let identifier = reveal.identifier, !isReading else { return }
        reveal.identifier = nil
        filter = .all
        query = identifier
        rows = matches
        selection = catalog?.rules.first { $0.identifier == identifier }?.id
    }

    /// The rules, sorted by the column picked, with each one's name, a mark on a report-only rule, its identifier
    /// and its rule file.
    private var table: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Name", value: \.name) { rule in
                HStack(spacing: 5) {
                    Text(rule.name).lineLimit(1).help(rule.name)
                    if rule.isReportOnly {
                        /// A symbol rather than the inspector's badge, which left no room for the name.
                        Image(systemName: "binoculars.fill")
                            .imageScale(.small)
                            .foregroundStyle(CalloutBadge.reportOnly.color)
                            .help(CalloutBadge.reportOnly.help)
                            .accessibilityLabel(CalloutBadge.reportOnly.text)
                    }
                }
            }
            /// The name gets the larger share, so a report-only rule's name stays readable beside its mark. The
            /// identifier mostly repeats it, and the inspector shows it whole.
            .width(min: 80, ideal: 205)
            TableColumn("Identifier", value: \.identifier) { rule in
                Text(rule.identifier).font(.body.monospaced()).lineLimit(1).help(rule.identifier)
            }
            .width(min: 60, ideal: 65)
            TableColumn("File", value: \.file.title) { rule in
                Text(rule.file.title)
            }
            .width(min: 44, ideal: 56, max: 64)
        }
        .tableStyle(.inset(alternatesRowBackgrounds: true))
        .overlay {
            if isReading {
                ProgressView("Reading this Mac's XProtect rules")
            } else if catalog != nil, rows.isEmpty {
                Text("No rules match.").foregroundStyle(.secondary)
            }
        }
    }

    /// The rules the filter and the search keep, in the table's order.
    private var matches: [XProtectRule] {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        return (catalog?.rules ?? []).filter { rule in
            filter.keeps(rule) && (query.isEmpty || [rule.name, rule.identifier, rule.uuid ?? ""]
                .contains { $0.lowercased().contains(query) })
        }
        .sorted(using: sortOrder)
    }

    /// What the header says: the XProtect version, how many rules there are, and whether they're loaded when the
    /// Security Extension says, or that none could be read.
    private var detail: String? {
        guard !isReading else { return nil }
        guard let catalog else { return "This Mac's XProtect rules can't be read." }
        let loaded = status.map { " · " + $0.summary(listing: catalog.version) } ?? ""
        return "XProtect \(catalog.version) · \(catalog.rules.count) rules" + loaded
    }
}


// MARK: - Showing a rule
/// The rule Event Facts' XProtect scan asked Settings to show, until Settings > XProtect Rules shows it. A scan names
/// a rule by its identifier alone, not its rule file.
final class XProtectRuleReveal: ObservableObject {
    static let shared = XProtectRuleReveal()
    /// The rule's identifier, until the pane takes it.
    @Published var identifier: String?
}


// MARK: - Rule files
extension XProtectRuleFile {
    /// Its name in the table.
    var title: String { self == .xprotect ? "Files" : "Scripts" }
    /// What it scans, after its name in the inspector.
    var gloss: String { self == .xprotect ? "every file scanned" : "what osascript runs" }
}
