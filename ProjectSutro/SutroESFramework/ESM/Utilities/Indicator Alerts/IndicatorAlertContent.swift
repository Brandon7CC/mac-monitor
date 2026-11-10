//
//  IndicatorAlertContent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - What a notification says
/// A notification's text and fields, from what the coalescer decided to post (``IndicatorAlert``). Mac Monitor hands
/// them to `UNUserNotificationCenter` as they are; nothing here imports it.
///
/// Every string from an event is cleaned and capped (``NotificationSafeText``): names and signing identifiers at 64
/// scalars, paths at 160 (cut in the middle, with the home folder as `~`), and the body at 320. Nothing an event's
/// ``IndicatorAlertEvent`` doesn't hold can show: no command line, argument, environment or script.
public struct IndicatorAlertContent: Equatable, Sendable {
    /// The category of an indicator's notice and summaries, with Show All Matches and Don't Notify. Its
    /// hidden-preview placeholder keeps paths off a locked screen.
    public static let category = "indicator.hit"
    /// The overflow summary's category, with Show All Matches only: it's for several indicators.
    public static let overflowCategory = "indicators.overflow"
    /// The overflow summary's identifier, so each replaces the last.
    public static let overflowIdentifier = "indicators.overflow"
    /// The most scalars of a name or signing identifier.
    static let nameLimit = 64
    /// The most scalars of a path.
    static let pathLimit = 160
    /// The most scalars of the body.
    static let bodyLimit = 320

    /// The request's identifier: an indicator's notice and its summaries share one, so a summary replaces the notice.
    public let identifier: String
    /// The title, such as "High: XProtect detection".
    public let title: String
    /// The subtitle.
    public let subtitle: String
    /// The body, in lines.
    public let body: String
    /// Does it play the default sound? Only a High does.
    public let playsSound: Bool
    /// What a click acts on.
    public let info: IndicatorAlertInfo

    /// The thread it's grouped in: its identifier.
    public var threadIdentifier: String { identifier }

    /// - Parameters:
    ///   - alert: What to post.
    ///   - now: The time now, by the wall clock, for an old event's time.
    ///   - home: This user's home folder, shown as `~`.
    ///   - limits: The numbers the coalescer follows: when an event says its time, and how many processes it counts.
    public init(_ alert: IndicatorAlert, now: Date = Date(), home: String = NSHomeDirectory(),
                limits: IndicatorAlertLimits = .standard) {
        switch alert {
        case .first(let event):
            let lines = Self.lines(of: event, home: home)
                + [Self.also(event)].compactMap { $0 }
                + (IndicatorAlertPolicy.age(of: event, now: now) > limits.showsTimeAfter
                   ? ["At " + Self.clockTime(event.time, style: .medium)] : [])
            self.init(event, subtitle: Self.process(event), lines: lines, kind: .first)
        case .summary(let summary):
            let processes = summary.processes.count
            let from = summary.hasMoreProcesses ? "\(processes) or more processes"
                : Self.counted(processes, "process", "processes")
            let subtitle = "\(Self.counted(summary.count, "more match", "more matches")) since "
                + "\(Self.clockTime(summary.since, style: .short)), from \(from)"
            self.init(summary.latest, subtitle: subtitle, lines: Self.lines(of: summary.latest, home: home),
                      kind: .summary)
        case .overflow(let overflow):
            let listed = overflow.entries.prefix(limits.overflowListed).map { entry in
                "\(NotificationSafeText.truncated(entry.indicator.name, to: Self.nameLimit)) (\(entry.count))"
            }.joined(separator: ", ")
            let rest = overflow.entries.count - min(overflow.entries.count, limits.overflowListed)
            self.init(identifier: Self.overflowIdentifier,
                      title: "Mac Monitor: " + Self.counted(overflow.count, "more indicator match",
                                                            "more indicator matches"),
                      subtitle: "",
                      body: NotificationSafeText.cut(
                        listed + (rest > 0 ? " and " + Self.counted(rest, "more indicator", "more indicators") : ""),
                        to: Self.bodyLimit),
                      playsSound: false, info: IndicatorAlertInfo(overflow))
        }
    }

    /// - Parameters:
    ///   - identifier: The request's identifier.
    ///   - title: The title.
    ///   - subtitle: The subtitle.
    ///   - body: The body.
    ///   - playsSound: Does it play the default sound?
    ///   - info: What a click acts on.
    private init(identifier: String, title: String, subtitle: String, body: String, playsSound: Bool,
                 info: IndicatorAlertInfo) {
        (self.identifier, self.title, self.subtitle) = (identifier, title, subtitle)
        (self.body, self.playsSound, self.info) = (body, playsSound, info)
    }

    /// A notice or summary of an indicator's event.
    ///
    /// - Parameters:
    ///   - event: The event: the notice's, or the summary's latest.
    ///   - subtitle: The subtitle.
    ///   - lines: The body's lines.
    ///   - kind: A notice or a summary.
    private init(_ event: IndicatorAlertEvent, subtitle: String, lines: [String], kind: IndicatorAlertInfo.Kind) {
        let indicator = event.indicator
        let name = NotificationSafeText.truncated(indicator.name, to: Self.nameLimit)
        let body = lines.filter { !$0.isEmpty }.joined(separator: "\n")
        let info = IndicatorAlertInfo(kind: kind, eventID: event.eventID, indicatorID: indicator.id, indicators: [])
        self.init(identifier: Self.identifier(of: indicator.id), title: "\(indicator.severity.name): \(name)",
                  subtitle: subtitle, body: NotificationSafeText.cut(body, to: Self.bodyLimit),
                  playsSound: indicator.severity == .high, info: info)
    }

    /// - Parameter indicator: An indicator's identity.
    /// - Returns: Its notices' identifier, `indicator.<uuid>`.
    public static func identifier(of indicator: UUID) -> String {
        "indicator." + indicator.uuidString
    }

    // MARK: Lines

    /// An event's first two lines: what it did, then its signing and ATT&CK.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - home: This user's home folder.
    /// - Returns: The lines, the second empty when there's nothing to say.
    static func lines(of event: IndicatorAlertEvent, home: String) -> [String] {
        let path = event.targetPath.map {
            NotificationSafeText.middleTruncated(NotificationSafeText.abbreviatingHome($0, home: home),
                                                 to: pathLimit)
        }
        let action = [NotificationSafeText.clean(event.eventName), path ?? ""].filter { !$0.isEmpty }
        let signing = [event.signingID.map { NotificationSafeText.truncated($0, to: nameLimit) },
                       event.isAdHoc ? "ad hoc" : nil, event.isUnsigned ? "unsigned" : nil].compactMap { $0 }
        let attack = [event.indicator.tactic, event.indicator.technique].compactMap { value in
            value.map { NotificationSafeText.truncated($0, to: nameLimit) }.flatMap { $0.isEmpty ? nil : $0 }
        }
        let second = [signing.joined(separator: ", "), attack.joined(separator: ", ")].filter { !$0.isEmpty }
        return [action.joined(separator: " "), second.joined(separator: ". ")]
    }

    /// - Parameter event: The event.
    /// - Returns: "Also: Ran a script, Download tool (+3 more)", or `nil` when it matched nothing else.
    static func also(_ event: IndicatorAlertEvent) -> String? {
        guard !event.others.isEmpty else { return nil }
        let names = event.others.map { NotificationSafeText.truncated($0, to: nameLimit) }.joined(separator: ", ")
        return "Also: " + names + (event.moreOthers > 0 ? " (+\(event.moreOthers) more)" : "")
    }

    /// - Parameter event: The event.
    /// - Returns: "osascript (pid 812)", with " as root" when its user isn't this app's.
    static func process(_ event: IndicatorAlertEvent) -> String {
        let file = NotificationSafeText.truncated((event.executablePath as NSString?)?.lastPathComponent ?? "",
                                                  to: nameLimit)
        let process = file.isEmpty ? "pid \(event.pid)" : "\(file) (pid \(event.pid))"
        return process + (event.user.map { " as " + NotificationSafeText.truncated($0, to: nameLimit) } ?? "")
    }

    /// - Parameters:
    ///   - count: A count.
    ///   - one: What one is called.
    ///   - many: What more are called.
    /// - Returns: Such as "1 more match" or "37 more matches".
    static func counted(_ count: Int, _ one: String, _ many: String) -> String {
        "\(count) \(count == 1 ? one : many)"
    }

    /// - Parameters:
    ///   - date: A time.
    ///   - style: How much of it: `.short` for 10:42, `.medium` for 10:42:03.
    /// - Returns: The local time of day, in this user's format.
    public static func clockTime(_ date: Date, style: DateFormatter.Style) -> String {
        DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: style)
    }
}
