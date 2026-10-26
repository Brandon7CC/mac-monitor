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
/// The findings Event Facts looks for, as Settings ▸ Findings edits them: Mac Monitor's defaults until they're changed,
/// kept in user defaults. Its matchers find them in Correlation, Groups, and the event tables.
@MainActor
final class FindingStore: ObservableObject {
    static let shared = FindingStore()

    @Published private(set) var findings: [Finding] {
        didSet {
            revision += 1
            matchers = [:]
            usableCache = nil
            marks.removeAllObjects()
            defaults.set(try? JSONEncoder().encode(findings), forKey: Self.key)
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
    private var matchers: [Tab: FindingMatcher] = [:]
    /// Each event's marks, by its object ID, found once until the findings change.
    private let marks = NSCache<NSManagedObjectID, EventMarks>()
    /// Mac Monitor's built-in marks, always on.
    private let builtInMarks = FindingMatcher(Finding.builtInMarks)

    /// The saved findings, without the built-in marks an earlier build saved among them.
    ///
    /// - Parameter defaults: Where the findings are kept.
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        findings = defaults.data(forKey: Self.key).flatMap { try? JSONDecoder().decode([Finding].self, from: $0) }
            .map(Finding.droppingBuiltInMarks) ?? Finding.defaults
    }

    /// The findings that are on and whose predicates can be used, worked out once until they change.
    var usable: [Finding] {
        if let usableCache { return usableCache }
        let usable = findings.filter { $0.isEnabled && $0.problem == nil }
        usableCache = usable
        return usable
    }
    private var usableCache: [Finding]?

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
    ///
    /// - Parameter message: An event on the main queue's context.
    /// - Returns: Its marks.
    func marks(for message: ESMessage) -> EventMarks {
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

    /// Put Mac Monitor's findings back, and drop the rest.
    func restoreDefaults() {
        findings = Finding.defaults
    }

    /// Are the findings Mac Monitor's own, unchanged?
    var isDefault: Bool { findings == Finding.defaults }
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
/// explanation as help. Settings ▸ Findings chooses which mark the tables.
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


/// A finding's symbol, drawn in its color, its palette, or the symbol's own colors.
struct FindingSymbol: View {
    let finding: Finding

    var body: some View {
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

    /// A built-in mark's help on an event. It's the mark's explanation, with the exec's executable age, its script's
    /// path and how it's adhoc signed in place of `{age}`, `{script}` and `{adhoc}`.
    ///
    /// - Parameter message: The event.
    /// - Returns: The help.
    func help(on message: ESMessage) -> String {
        guard explanation.contains("{"), let exec = message.event.exec else { return explanation }
        let adhoc = exec.target.isLinkerSignedAdhoc
            ? "Adhoc signed by the linker, as a freshly compiled binary is." : "Adhoc signed."
        return explanation.replacingOccurrences(of: "{age}", with: exec.executableAgeText ?? "")
            .replacingOccurrences(of: "{script}", with: exec.resolved_script_path ?? "a script")
            .replacingOccurrences(of: "{adhoc}", with: adhoc)
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
