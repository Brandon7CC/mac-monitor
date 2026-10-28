//
//  FindingStore.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/25/26.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Store
/// The findings Event Facts looks for, as Settings ▸ Indicators edits them: Mac Monitor's defaults until they're
/// changed, kept in user defaults. Its matchers find them in Correlation, Groups, and the event tables.
@MainActor
final class FindingStore: ObservableObject {
    static let shared = FindingStore()

    /// Only an edit saves them. Loading never does, so saved findings that didn't decode stay as they are until then.
    @Published private(set) var findings: [Finding] {
        didSet {
            revision += 1
            matchers = [:]
            offeredCache = nil
            marks.removeAllObjects()
            saved.findings = findings
            defaults.set(saved.encoded(), forKey: Self.key)
        }
    }
    /// Changes with every edit, for views to make their summaries again.
    @Published private(set) var revision = 0

    /// Where findings show.
    enum Tab {
        case correlation, groups, tables
    }

    private static let key = "findings"
    private let defaults: UserDefaults
    /// The findings as saved, with the entries this build couldn't decode, which are written back after the rest.
    private var saved: SavedFindings
    private var matchers: [Tab: FindingMatcher] = [:]
    /// Each event's marks, by its object ID, found once until the findings change.
    private let marks = NSCache<NSManagedObjectID, EventMarks>()
    /// Mac Monitor's built-in marks, always on.
    private let builtInMarks = FindingMatcher(Finding.builtInMarks)

    /// The saved findings that decode, or Mac Monitor's defaults when none were saved or they aren't an array.
    ///
    /// - Parameter defaults: Where the findings are kept.
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        saved = defaults.data(forKey: Self.key).flatMap(SavedFindings.init(data:)) ?? SavedFindings(Finding.defaults)
        findings = saved.findings
    }

    /// The findings the Filters sheet offers (``FindingSelection/offered(_:)``). Their predicates are parsed once until
    /// the findings change.
    var offered: [Finding] {
        if let offeredCache { return offeredCache }
        let offered = FindingSelection.offered(findings)
        offeredCache = offered
        return offered
    }
    private var offeredCache: [Finding]?

    /// The findings on for a tab, parsed once until they change.
    ///
    /// - Parameter tab: Correlation, Groups, or the event tables.
    /// - Returns: Its matcher.
    func matcher(for tab: Tab) -> FindingMatcher {
        if let matcher = matchers[tab] { return matcher }
        let matcher = FindingMatcher(findings.filter { finding in
            switch tab {
            case .correlation: return finding.showsInCorrelation
            case .groups: return finding.showsInGroups
            case .tables: return finding.showsInTables
            }
        })
        matchers[tab] = matcher
        return matcher
    }

    /// The built-in marks an event matches, and the findings that mark it in the tables, as a script's exec is marked.
    /// An event that's gone has none, as a Clear's events are while the views let go of them.
    ///
    /// - Parameter message: An event on the main queue's context.
    /// - Returns: Its marks.
    func marks(for message: ESMessage) -> EventMarks {
        guard !message.isDeleted, message.es_event_type != nil else { return EventMarks(builtIn: [], findings: []) }
        if let found = marks.object(forKey: message.objectID) { return found }
        let found = EventMarks(builtIn: Set(builtInMarks.matches(message).map(\.id)),
                               findings: matcher(for: .tables).matches(message))
        marks.setObject(found, forKey: message.objectID)
        return found
    }

    /// Add a finding, or replace the one with its identity.
    ///
    /// - Parameter finding: The finding.
    func save(_ finding: Finding) {
        if let index = findings.firstIndex(where: { $0.id == finding.id }) {
            findings[index] = finding
        } else {
            findings.append(finding)
        }
    }

    /// - Parameter finding: A finding to forget.
    func delete(_ finding: Finding) {
        findings.removeAll { $0.id == finding.id }
    }

    /// Put Mac Monitor's findings back, and drop the rest, those that didn't decode too.
    func restoreDefaults() {
        saved = SavedFindings(Finding.defaults)
        findings = Finding.defaults
    }

    /// Are the findings Mac Monitor's own, unchanged?
    var isDefault: Bool { findings == Finding.defaults && saved.undecodableCount == 0 }
}


// MARK: - Event tables
/// The built-in marks an event matches, and the findings that mark it in the tables.
final class EventMarks {
    /// The built-in marks it matches, by identity.
    let builtIn: Set<UUID>
    /// The findings that mark it in the tables, in order.
    let findings: [Finding]

    /// - Parameters:
    ///   - builtIn: The built-in marks it matches.
    ///   - findings: The findings that mark it in the tables.
    init(builtIn: Set<UUID>, findings: [Finding]) {
        self.builtIn = builtIn
        self.findings = findings
    }

    /// - Parameter marks: Built-in marks, such as ``Finding/labelMarks``.
    /// - Returns: Those it matches, in their order.
    func matched(_ marks: [Finding]) -> [Finding] {
        marks.filter { builtIn.contains($0.id) }
    }
}


/// An event's findings that mark it in the tables, before its type or name. Each shows its symbol, with its name and
/// explanation as help. Settings ▸ Indicators chooses which mark the tables.
struct FindingMarks: View {
    let message: ESMessage
    /// The built-in marks drawn beside them. A finding that's a matched mark's twin isn't drawn again.
    var besides: [Finding] = []
    @ObservedObject private var store = FindingStore.shared

    var body: some View {
        let marks = store.marks(for: message)
        ForEach(Finding.findings(marks.findings, besides: marks.matched(besides))) { finding in
            FindingSymbol(finding: finding).help("\(finding.name): \(finding.explanation)")
        }
    }
}


/// The built-in marks an event matches, as its hard-coded label drew them. Each shows its symbol, with its help. A
/// multicolor mark sits 2 points further from the one before it.
struct BuiltInMarks: View {
    let message: ESMessage
    /// The marks to look for, in order, such as ``Finding/labelMarks``.
    let marks: [Finding]

    var body: some View {
        ForEach(FindingStore.shared.marks(for: message).matched(marks)) { mark in
            FindingSymbol(finding: mark)
                .padding(.leading, mark.rendering == .multicolor ? 2 : 0)
                .help(ifAny: mark.help(on: message))
        }
    }
}


/// A finding's symbol, drawn in its color, its palette, or the symbol's own colors. VoiceOver reads its name.
struct FindingSymbol: View {
    let finding: Finding

    var body: some View {
        symbol.accessibilityLabel(finding.name)
    }

    @ViewBuilder
    private var symbol: some View {
        let image = Image(systemName: finding.symbol)
        let layers = finding.palette.map(\.swiftUI)
        switch finding.rendering {
        case .multicolor:
            image.symbolRenderingMode(.multicolor)
        case .palette where layers.count > 2:
            image.symbolRenderingMode(.palette).foregroundStyle(layers[0], layers[1], layers[2])
        case .palette where layers.count == 2:
            image.symbolRenderingMode(.palette).foregroundStyle(layers[0], layers[1])
        case .palette:
            image.symbolRenderingMode(.palette).foregroundStyle(layers.first ?? finding.tint)
        case .monochrome:
            image.foregroundStyle(finding.tint)
        }
    }
}


// MARK: - Presentation
extension Finding {
    /// Its color, as SwiftUI draws it. `SwiftUI.Color`: here `Color` is ``Finding/Color``.
    var tint: SwiftUI.Color { color.swiftUI }

    /// Its card's title.
    ///
    /// - Parameter count: How many events are part of it.
    /// - Returns: Its name, and how many when there's more than one: "Quarantine removed ×3".
    func title(_ count: Int) -> String {
        count > 1 ? "\(name) ×\(count)" : name
    }

    /// A built-in mark's help on an event. It's the mark's explanation, with the exec's executable age and its
    /// script's path in place of `{age}` and `{script}`.
    ///
    /// - Parameter message: The event.
    /// - Returns: The help.
    func help(on message: ESMessage) -> String {
        guard explanation.contains("{"), let exec = message.event.exec else { return explanation }
        return explanation.replacingOccurrences(of: "{age}", with: exec.executableAgeText ?? "")
            .replacingOccurrences(of: "{script}", with: exec.resolved_script_path ?? "a script")
    }
}


extension View {
    /// - Parameter text: Its help, or "" for none.
    /// - Returns: The view, with the help when there's some.
    @ViewBuilder
    func help(ifAny text: String) -> some View {
        if text.isEmpty {
            self
        } else {
            help(text)
        }
    }
}


extension Finding.Color {
    /// The color, as SwiftUI draws it.
    var swiftUI: SwiftUI.Color {
        switch self {
        case .red: return .red
        case .orange: return .orange
        case .yellow: return .yellow
        case .green: return .green
        case .teal: return .teal
        case .blue: return .blue
        case .indigo: return .indigo
        case .purple: return .purple
        case .pink: return .pink
        case .gray: return .gray
        case .black: return .black
        case .primary: return .primary
        }
    }
}
