//
//  IndicatorStore.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/25/26.
//

import SwiftUI
import Combine
import CoreData
import SutroESFramework


// MARK: - Store
/// The indicators Event Facts looks for, as Settings > Indicators edits them: the Mac's indicator set, which the
/// Security Extension keeps and stamps every event with (``IndicatorEngine``), as this user sees it. Each indicator's
/// view switches, where it shows in Correlation, Groups and the tables, are this user's (``IndicatorOverlay``); the
/// rest is the Mac's, and every change to it is a request to the Security Extension. Its matchers find them in
/// Correlation, Groups, and the event tables, from each event's stored verdicts when it has them.
@MainActor
final class IndicatorStore: ObservableObject {
    static let shared = IndicatorStore()

    /// The Mac's indicators, with this user's view switches.
    @Published private(set) var indicators: [Indicator] {
        didSet {
            revision += 1
            eventMatcher = nil
            recordIndicators = nil
            offeredCache = nil
            localProblems = nil
            silencedTwins = Self.silencedTwins(of: indicators)
            marks.removeAllObjects()
        }
    }
    /// Changes with every edit, for views to make their summaries again.
    @Published private(set) var revision = 0
    /// This user's Mac Monitor 3.0 indicators, offered to the Mac's set once it's known, until taken or declined.
    @Published private(set) var importOffer: IndicatorImportOffer?
    /// The indicator Event Facts' Indicators popover asked to show, until Settings > Indicators scrolls to it.
    @Published var revealRequest: UUID?

    /// The Mac's indicator set.
    let engine: IndicatorEngine
    /// The connection the engine asks over, once there is one.
    private weak var connected: EndpointSecurityManager?
    /// This user's view switches.
    private var overlay: IndicatorOverlay
    private let defaults: UserDefaults
    /// The engine's changes, and Mac Monitor becoming active.
    private var observers: [AnyCancellable] = []
    /// Finds each event's indicators, made once until the indicators change.
    private var eventMatcher: EventIndicatorMatcher?
    /// Each event's marks, by its object ID, found once until the indicators change. The tables' visible rows and a
    /// scroll's worth either side fit many times over.
    private let marks: NSCache<NSManagedObjectID, EventMarks> = {
        let marks = NSCache<NSManagedObjectID, EventMarks>()
        marks.countLimit = 20_000
        return marks
    }()
    /// The built-in marks that are an indicator's twin, which follow it: drawn when it matches, while it's on and
    /// marks the tables with its symbol.
    private static let twins = Set(Indicator.builtInMarks.map(\.id)).intersection(Indicator.defaults.map(\.id))
    /// Mac Monitor's other built-in marks, always on. A twin's match is its indicator's.
    private let builtInMarks = IndicatorMatcher(Indicator.builtInMarks.filter { !IndicatorStore.twins.contains($0.id) })
    /// The twins not drawn, as the indicators are now.
    private var silencedTwins: Set<UUID> = []

    /// - Parameter indicators: The indicators.
    /// - Returns: The twins whose indicator is off, deleted, or doesn't draw its symbol.
    private static func silencedTwins(of indicators: [Indicator]) -> Set<UUID> {
        twins.subtracting(indicators.filter { $0.isEnabled && $0.showsInTables }.map(\.id))
    }

    /// The last set the Security Extension sent, with this user's view switches, until ``connect(_:)``.
    ///
    /// - Parameters:
    ///   - defaults: Where the last set and the view switches are kept.
    ///   - engine: The Mac's indicator set, which asks for nothing until it's connected.
    init(defaults: UserDefaults = .standard, engine: IndicatorEngine? = nil) {
        self.defaults = defaults
        let engine = engine ?? IndicatorEngine(defaults: defaults)
        self.engine = engine
        overlay = IndicatorOverlay(defaults: defaults)
        indicators = overlay.applied(to: engine.indicators)
        silencedTwins = Self.silencedTwins(of: indicators)
        follow(engine)
    }

    /// Ask for the Mac's indicators over Mac Monitor's connection to the Security Extension from now on. Again does
    /// nothing.
    ///
    /// - Parameter manager: Mac Monitor's connection to the Security Extension.
    func connect(_ manager: EndpointSecurityManager) {
        guard connected !== manager else { return }
        connected = manager
        engine.connect(manager.indicatorTransport)
    }

    /// Republish the engine's changes, make the indicators again when its set or connection does, and ask for the set
    /// again when the Security Extension is ready, and when Mac Monitor becomes active once it was asked. A
    /// `@Published` value is sent before it's set, so the indicators are made again on the next turn of the main queue.
    ///
    /// - Parameter engine: The engine.
    private func follow(_ engine: IndicatorEngine) {
        let changes = engine.$indicators.map { _ in () }.merge(with: engine.$connection.map { _ in () })
        observers = [
            engine.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() },
            changes.dropFirst(2).receive(on: DispatchQueue.main).sink { [weak self] _ in self?.rebuild() },
            NotificationCenter.default.publisher(for: IndicatorEngine.sensorReady).sink { _ in engine.refresh() },
            NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification).sink { _ in
                if engine.connection != .waiting { engine.refresh() }
            },
        ]
    }

    /// Make the indicators again from the engine's set and the view switches, and the 3.0 offer once the set is the
    /// Security Extension's.
    private func rebuild() {
        let next = overlay.applied(to: engine.indicators)
        if next != indicators { indicators = next }
        if engine.connection == .connected {
            importOffer = IndicatorImportOffer.pending(in: defaults, mac: engine.indicators)
        }
    }

    /// The indicators the Filters sheet offers (``IndicatorSelection/offered(_:)``). Their predicates are parsed once
    /// until the indicators change.
    var offered: [Indicator] {
        if let offeredCache { return offeredCache }
        let offered = IndicatorSelection.offered(indicators)
        offeredCache = offered
        return offered
    }
    private var offeredCache: [Indicator]?

    /// The indicators records list, parsed once until they change.
    private var recordIndicators: RecordIndicators?

    /// An event's record, pretty-printed as Export telemetry writes it, with its indicators under `indicators`: the
    /// Security Extension's verdicts, or those it matches now: what the JSON tab shows and ⌘C copies.
    ///
    /// - Parameter message: An event on the main queue's context.
    /// - Returns: The record.
    func json(of message: ESMessage) -> String {
        let listed = recordIndicators ?? RecordIndicators(indicators)
        recordIndicators = listed
        return RecordIndicators.encoding(with: listed) {
            ProcessHelpers.eventToJSON(value: message, pretty: true)
        }
    }

    /// The matcher for every indicator that's on, parsed once until they change. Correlation, Groups, the tables'
    /// dots and Event Facts' Indicators popover all show every one: an indicator's own Correlation and Groups switches
    /// are kept, but not read. It reads each event's stored verdicts first.
    var matcher: EventIndicatorMatcher {
        if let eventMatcher { return eventMatcher }
        let matcher = EventIndicatorMatcher(indicators)
        eventMatcher = matcher
        return matcher
    }

    /// The built-in marks an event matches, and the indicators it matched: its stored verdicts, else every indicator
    /// that's on it matches, as a script's exec is marked. An event that's gone has none, as a Clear's events are
    /// while the views let go of them.
    ///
    /// - Parameter message: An event on the main queue's context.
    /// - Returns: Its marks.
    func marks(for message: ESMessage) -> EventMarks {
        guard !message.isDeleted, message.es_event_type != nil else { return EventMarks(builtIn: [], indicators: []) }
        if let found = marks.object(forKey: message.objectID) { return found }
        let matched = matcher.matches(message)
        let twins = Set(matched.filter(\.isEnabled).map(\.id)).intersection(Self.twins).subtracting(silencedTwins)
        let found = EventMarks(builtIn: Set(builtInMarks.matches(message).map(\.id)).union(twins),
                               indicators: matched)
        marks.setObject(found, forKey: message.objectID)
        return found
    }

    // MARK: Problems

    /// Why the Security Extension can't run each indicator, worked out here, until it says.
    private var localProblems: [UUID: String]?

    /// - Parameter indicator: An indicator.
    /// - Returns: Why the Security Extension can't run it, as it said, or as Mac Monitor works it out before it has.
    func sensorProblem(of indicator: Indicator) -> String? {
        if engine.connection == .connected { return engine.problems[indicator.id] }
        if localProblems == nil {
            let problems = indicators.compactMap { indicator in indicator.sensorProblem.map { (indicator.id, $0) } }
            localProblems = Dictionary(problems) { first, _ in first }
        }
        return localProblems?[indicator.id]
    }
}


// MARK: - Changes
extension IndicatorStore {
    /// May this Mac Monitor change the Mac's indicators? View switches are this user's, and always change.
    var canChangeIndicators: Bool { engine.canChangeIndicators }

    /// Keep an indicator as it's been edited: its view switches as this user's, and, as the Mac's, only what changed
    /// from the copy the editor or row started from (``IndicatorEngine/change(_:from:)``), so a change `macmonitor`
    /// or another user made meanwhile stays.
    ///
    /// - Parameters:
    ///   - indicator: The indicator, new or changed.
    ///   - original: The indicator as the editor or row started from it, or `nil` for a new one.
    func save(_ indicator: Indicator, from original: Indicator?) {
        if overlay.keep(indicator, mac: engine.indicators.first { $0.id == indicator.id }) {
            overlay.save(to: defaults)
            rebuild()
        }
        engine.change(indicator, from: original)
    }

    /// Turn indicators on or off, in one request.
    ///
    /// - Parameters:
    ///   - indicators: The indicators.
    ///   - on: On or off.
    func setEnabled(_ indicators: [Indicator], _ on: Bool) {
        let ids = indicators.filter { $0.isEnabled != on }.map(\.id)
        if !ids.isEmpty { engine.setEnabled(ids, on) }
    }

    /// Ask Settings > Indicators to show an indicator, once it shows (``ShowInSettingsButton`` opens Settings).
    ///
    /// - Parameter id: The indicator's identity.
    func requestReveal(_ id: UUID) {
        revealRequest = id
    }

    /// - Parameter indicator: An indicator to remove from the Mac's set.
    func delete(_ indicator: Indicator) {
        engine.remove([indicator.id])
    }

    /// Put Mac Monitor's indicators back, for the Mac, and this user's view switches.
    func restoreDefaults() {
        overlay.removeAll()
        overlay.save(to: defaults)
        rebuild()
        engine.restoreDefaults()
    }

    /// Are the indicators Mac Monitor's own, unchanged, and is every view switch as the Mac has it?
    var isDefault: Bool { engine.isDefault && overlay.views.isEmpty }

    /// Add this user's Mac Monitor 3.0 indicators to the Mac's set. Once the Security Extension takes them, the offer
    /// isn't made again.
    ///
    /// - Parameter replacingEdited: Do their edited shipped indicators replace the Mac's versions too?
    func takeImportOffer(replacingEdited: Bool) {
        guard let offer = importOffer else { return }
        engine.send(offer.request(replacingEdited: replacingEdited)) { [weak self] reply in
            guard let self, reply?.status == .ok else { return }
            IndicatorImportOffer.markOffered(in: defaults)
            importOffer = nil
        }
    }

    /// Don't offer this user's Mac Monitor 3.0 indicators again.
    func declineImportOffer() {
        IndicatorImportOffer.markOffered(in: defaults)
        importOffer = nil
    }
}
