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
    /// Each event's marks in the tables, by its object ID, found once until the findings change.
    private let marks = NSCache<NSManagedObjectID, NSArray>()

    /// - Parameter defaults: Where the findings are kept.
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        findings = defaults.data(forKey: Self.key).flatMap { try? JSONDecoder().decode([Finding].self, from: $0) }
            ?? Finding.defaults
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

    /// The findings that mark an event in the tables, as a script's exec is marked.
    ///
    /// - Parameter message: An event on the main queue's context.
    /// - Returns: Its findings, in order.
    func marks(for message: ESMessage) -> [Finding] {
        if let found = marks.object(forKey: message.objectID) as? [Finding] { return found }
        let found = matcher(for: .tables).matches(message)
        marks.setObject(found as NSArray, forKey: message.objectID)
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
/// An event's findings that mark it in the tables, before its name: each one's symbol in its color, its name and
/// why as its help. Settings ▸ Findings chooses which mark the tables.
struct FindingMarks: View {
    let message: ESMessage
    @ObservedObject private var store = FindingStore.shared

    var body: some View {
        ForEach(store.marks(for: message)) { finding in
            Image(systemName: finding.symbol)
                .foregroundStyle(finding.tint)
                .help("\(finding.name): \(finding.explanation)")
        }
    }
}


// MARK: - Presentation
extension Finding {
    /// Its color, as SwiftUI draws it. `SwiftUI.Color`: here `Color` is ``Finding/Color``.
    var tint: SwiftUI.Color {
        switch color {
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
        }
    }

    /// Its card's title.
    ///
    /// - Parameter count: How many events are part of it.
    /// - Returns: Its name, and how many when there's more than one: "Quarantine removed ×3".
    func title(_ count: Int) -> String {
        count > 1 ? "\(name) ×\(count)" : name
    }
}
