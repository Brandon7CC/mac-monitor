//
//  IndicatorPackOffer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - A newer pack
/// A newer indicator pack the Security Extension found, as Mac Monitor offers it: which release it is, what the pack
/// and its release say of it, and what installing it would do to this Mac's indicators (agent context).
public struct IndicatorPackOffer: Equatable, Identifiable, Sendable {
    /// Which release it is.
    public let sequence: Int
    /// The names of the indicators it adds, in the pack's order.
    public var added: [String] = []
    /// The names of those it removes.
    public var removed: [String] = []
    /// The names of those it changes.
    public var changed: [String] = []
    /// How many indicators this Mac has once it's installed.
    public var total = 0
    /// When the pack's commit was made, as the pack says it.
    public var published: String?
    /// What its release says of it on GitHub, as Markdown. Unlike the rest, it isn't signed.
    public var notes: String?

    /// Identifies the offer by its release.
    public var id: Int { sequence }

    /// - Parameters:
    ///   - sequence: Which release it is.
    ///   - added: The names of the indicators it adds.
    ///   - removed: The names of those it removes.
    ///   - changed: The names of those it changes.
    ///   - total: How many indicators this Mac has once it's installed.
    ///   - published: When the pack's commit was made.
    ///   - notes: What its release says of it.
    public init(sequence: Int, added: [String] = [], removed: [String] = [], changed: [String] = [], total: Int = 0,
                published: String? = nil, notes: String? = nil) {
        self.sequence = sequence
        self.added = added
        self.removed = removed
        self.changed = changed
        self.total = total
        self.published = published
        self.notes = notes
    }

    /// The offer a check's answer makes, if it found a later release than this Mac has.
    ///
    /// - Parameters:
    ///   - preview: The Security Extension's answer to a check: the set as installing the pack would leave it.
    ///   - indicators: The set as it stands.
    ///   - pack: The release this Mac has.
    /// - Returns: The offer, or `nil` when the check found nothing later.
    init?(_ preview: IndicatorReply, over indicators: [Indicator], pack: IndicatorPackStatus?) {
        guard preview.status == .ok, let found = preview.pack, found.sequence > (pack?.sequence ?? 0) else {
            return nil
        }
        let next = Indicator.byID(preview.indicators)
        let current = Set(indicators.map(\.id))
        self.init(sequence: found.sequence,
                  added: preview.indicators.filter { !current.contains($0.id) }.map(\.name),
                  removed: indicators.filter { next[$0.id] == nil }.map(\.name),
                  changed: indicators.compactMap { old in next[old.id].flatMap { $0 == old ? nil : $0.name } },
                  total: preview.indicators.count, published: found.published, notes: preview.notes)
    }

    /// What installing it would do, as the rest of a sentence: such as "adds 3 indicators, removes 1 and changes 5",
    /// leaving out what it doesn't do, or "changes none of this Mac's indicators".
    public var effect: String {
        let parts = [added.isEmpty ? nil : "adds \(String.counted(added.count, "indicator"))",
                     removed.isEmpty ? nil : "removes \(removed.count)",
                     changed.isEmpty ? nil : "changes \(changed.count)"].compactMap { $0 }
        guard let last = parts.last else { return "changes none of this Mac's indicators" }
        return parts.count == 1 ? last : parts.dropLast().joined(separator: ", ") + " and " + last
    }

    /// The page of its release on GitHub.
    public var page: URL {
        IndicatorPackRelease.page(of: sequence)
    }
}


// MARK: - A look's outcome
/// How Mac Monitor's look for a newer indicator pack went.
public enum IndicatorPackLook: Equatable, Sendable {
    /// A newer pack is out.
    case newer(IndicatorPackOffer)
    /// This Mac has the newest pack.
    case upToDate
    /// GitHub couldn't be asked, the pack wasn't one Mac Monitor installs, or the Security Extension didn't answer:
    /// why, as the user reads it.
    case failed(String)
}


// MARK: - What Settings says
/// What Settings > General says about the indicator pack and the update mode.
public enum IndicatorPackText {
    /// - Parameter pack: What the Security Extension says of the pack, or `nil` when it hasn't said.
    /// - Returns: The pack row's title, such as "Indicator pack 2".
    public static func title(_ pack: IndicatorPackStatus?) -> String {
        guard let pack, pack.sequence > 0 else { return "Indicator pack" }
        return "Indicator pack \(pack.sequence)"
    }

    /// The pack row's second line: what the last look found, and when it was.
    ///
    /// - Parameters:
    ///   - pack: What the Security Extension says of the pack, or `nil` when it hasn't said.
    ///   - isLooking: Is a look under way?
    ///   - now: The time.
    ///   - locale: The locale the time since the last look is said in.
    /// - Returns: Such as "Up to date. Checked 2 hours ago."
    public static func detail(_ pack: IndicatorPackStatus?, isLooking: Bool = false, now: Date = Date(),
                              locale: Locale = .current) -> String {
        if isLooking { return "Looking for a newer pack." }
        guard let pack else { return "The Security Extension hasn't said which indicators it has." }
        let own = pack.sequence == 0 ? "Mac Monitor's own indicators are the ones this build came with." : nil
        if let problem = pack.problem { return problem }
        if let available = pack.available { return "Pack \(available) is out." }
        guard let checked = pack.checked.flatMap({ ISO8601DateFormatter().date(from: $0) }) else {
            return own ?? "It hasn't looked for a newer pack yet."
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        formatter.unitsStyle = .full
        /// A look in the last minute reads as "now" rather than "in 0 seconds".
        let ago = now.timeIntervalSince(checked) < 60 ? "just now"
            : formatter.localizedString(for: checked, relativeTo: now)
        return "\(own ?? "Up to date.") Checked \(ago)."
    }

    // MARK: The offer's sheet

    /// - Parameters:
    ///   - offer: A newer pack.
    ///   - pack: What the Security Extension says of the pack this Mac has.
    /// - Returns: Such as "Indicator pack 2 is available. You have pack 1."
    public static func availability(of offer: IndicatorPackOffer, over pack: IndicatorPackStatus?) -> String {
        let has = (pack?.sequence ?? 0) > 0 ? "pack \(pack?.sequence ?? 0)"
            : "the indicators this Mac Monitor came with"
        return "Indicator pack \(offer.sequence) is available. You have \(has)."
    }

    /// - Parameters:
    ///   - offer: A newer pack.
    ///   - pack: What the Security Extension says of the pack this Mac has.
    /// - Returns: This Mac's version, an arrow and the pack's, such as v0 then v2. A build's own indicators are v0.
    public static func versions(of offer: IndicatorPackOffer, over pack: IndicatorPackStatus?) -> String {
        "v\(pack?.sequence ?? 0) → v\(offer.sequence)"
    }

    /// The day a pack's commit was made, in this Mac's calendar, such as "November 15, 2026".
    ///
    /// - Parameters:
    ///   - published: When it was made, as the pack says it.
    ///   - timeZone: The time zone the day is in. Tests pass one.
    /// - Returns: The day, or `nil` when the pack gives no date or one that isn't ISO 8601.
    public static func day(_ published: String?, in timeZone: TimeZone = .current) -> String? {
        guard let published, let date = ISO8601DateFormatter().date(from: published) else { return nil }
        var style = Date.FormatStyle(date: .long, time: .omitted)
        style.timeZone = timeZone
        return date.formatted(style)
    }

    /// - Parameter mode: An update mode.
    /// - Returns: Its name in the picker.
    public static func name(of mode: IndicatorPackMode) -> String {
        switch mode {
        case .off: "Off"
        case .notify: "Notify me"
        case .automatic: "Install automatically"
        }
    }

    /// - Parameter mode: An update mode, or `nil` when the Security Extension hasn't said.
    /// - Returns: What it does, as the mode row's second line.
    public static func detail(of mode: IndicatorPackMode?) -> String {
        switch mode {
        case .off?: "Mac Monitor never looks for a newer indicator pack on its own."
        case .notify?: "Mac Monitor looks once a day, and tells you when a newer indicator pack is out."
        case .automatic?: "Mac Monitor looks once a day, and installs a newer indicator pack for every user."
        case nil: "How Mac Monitor takes newer indicator packs, for every user of this Mac."
        }
    }
}
