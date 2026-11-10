//
//  IndicatorAlertContentTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What a notification says
/// Pins a notification's text and fields: titles, subtitles and body lines, caps, the time of an old event, the
/// summary and overflow wording, identifiers, and that no command line, argument, environment or script reaches it.
final class IndicatorAlertContentTests: XCTestCase {
    private let home = "/Users/analyst"
    private let now = Date()

    /// A candidate from an exec of `/usr/bin/launchctl` (pid 812) that created a LaunchAgent.
    ///
    /// - Parameters:
    ///   - hits: Its hits. The first is the notification's.
    ///   - change: Changes the event further.
    /// - Returns: The candidate.
    private func event(_ hits: [IndicatorHit] = [], age: TimeInterval = 0,
                       _ change: (inout Message) -> Void = { _ in }) throws -> IndicatorAlertEvent {
        let hits = hits.isEmpty ? [alertHit("Launch job loaded", .high)] : hits
        let message = try alertMessage(hits, time: now.addingTimeInterval(-age)) { message in
            message.es_event_type = "ES_EVENT_TYPE_NOTIFY_CREATE"
            message.target_path = "/Users/analyst/Library/LaunchAgents/com.x.plist"
            message.process.executable?.path = "/usr/bin/launchctl"
            message.process.pid = 812
            message.process.euid = Int(getuid())
            message.process.signing_id = "com.apple.xpc.launchctl"
            message.process.codesigning_type = .platform
            message.process.is_adhoc_signed = false
            change(&message)
        }
        let event = try XCTUnwrap(IndicatorAlertPolicy.pick(message, settings: .init(high: true, medium: true),
                                                            disabled: []))
        return event
    }

    /// - Parameter alert: What to post.
    /// - Returns: Its content, for this test's home folder and time.
    private func content(_ alert: IndicatorAlert) -> IndicatorAlertContent {
        IndicatorAlertContent(alert, now: now, home: home)
    }

    /// A first notice: the severity and name, the process, what it did with the home folder as `~`, its signing and
    /// ATT&CK, with the default sound for High only.
    func testAFirstNotice() throws {
        let notice = content(.first(try event()))
        XCTAssertEqual(notice.title, "High: Launch job loaded")
        XCTAssertEqual(notice.subtitle, "launchctl (pid 812)")
        XCTAssertEqual(notice.body, "create ~/Library/LaunchAgents/com.x.plist\n"
                       + "com.apple.xpc.launchctl. Persistence, T1543.001")
        XCTAssertTrue(notice.playsSound)
        XCTAssertFalse(content(.first(try event([alertHit("Dylib", .medium)]))).playsSound)
        XCTAssertEqual(content(.first(try event([alertHit("Dylib", .medium)]))).title, "Medium: Dylib")
    }

    /// The subtitle names another user's process by user, and a process without an executable by pid. Ad hoc and
    /// unsigned processes say so.
    func testTheProcessAndItsSigning() throws {
        let root = try event { $0.process.euid = 0; $0.process.euid_human = "root" }
        XCTAssertEqual(content(.first(root)).subtitle, "launchctl (pid 812) as root")
        XCTAssertEqual(content(.first(try event { $0.process.executable = nil })).subtitle, "pid 812")
        let adHoc = try event { $0.process.signing_id = "a.out"; $0.process.codesigning_type = .adhoc }
        XCTAssertTrue(content(.first(adHoc)).body.hasSuffix("\na.out, ad hoc. Persistence, T1543.001"))
        let unsigned = try event { $0.process.signing_id = nil; $0.process.codesigning_type = .unsigned }
        XCTAssertTrue(content(.first(unsigned)).body.hasSuffix("\nunsigned. Persistence, T1543.001"))
    }

    /// The event's other hits are named, two and a count of the rest. An event older than a minute says when.
    func testOtherHitsAndAnOldEventsTime() throws {
        let hits = [alertHit("XProtect", .high), alertHit("Ran a script", .low), alertHit("Adhoc", .medium),
                    alertHit("Download tool", .low), alertHit("Login", .low)]
        let lines = content(.first(try event(hits, age: 61))).body.components(separatedBy: "\n")
        XCTAssertEqual(lines[2], "Also: Adhoc, Ran a script (+2 more)")
        XCTAssertEqual(lines[3], "At " + IndicatorAlertContent.clockTime(now.addingTimeInterval(-61), style: .medium))
        XCTAssertEqual(content(.first(try event(age: 60))).body.components(separatedBy: "\n").count, 2)
    }

    /// Names are capped at 64 scalars, paths at 160 (cut in the middle), and the body at 320, and every string is
    /// cleaned.
    func testCapsAndCleaning() throws {
        let long = try event([alertHit(String(repeating: "N", count: 100) + "\nx", .high)]) {
            $0.target_path = "/tmp/" + String(repeating: "p", count: 400) + "\u{202E}.plist"
            $0.process.signing_id = String(repeating: "s", count: 100)
        }
        let notice = content(.first(long))
        XCTAssertEqual(notice.title, "High: " + String(repeating: "N", count: 63) + "\u{2026}")
        let lines = notice.body.components(separatedBy: "\n")
        XCTAssertEqual(lines[0].unicodeScalars.count, "create ".count + 160)
        XCTAssertTrue(lines[0].hasSuffix("pppp.plist"))
        XCTAssertTrue(lines[1].hasPrefix(String(repeating: "s", count: 63) + "\u{2026}"))
        let others = (0..<10).map { _ in alertHit(String(repeating: "o", count: 64), .low) }
        let crowded = content(.first(try event([alertHit("Top", .high)] + others, age: 600) {
            $0.target_path = "/tmp/" + String(repeating: "p", count: 400)
            $0.process.signing_id = String(repeating: "s", count: 100)
        }))
        XCTAssertEqual(crowded.body.unicodeScalars.count, 320)
        XCTAssertTrue(crowded.body.hasSuffix("\u{2026}"))
        XCTAssertFalse(crowded.body.unicodeScalars.contains { TerminalSafeText.bidiControls.contains($0.value) })
    }

    /// A summary keeps the notice's title and identifier, so it replaces it, and counts its matches and processes.
    func testASummary() throws {
        let hit = alertHit("Launch job loaded", .high)
        let first = try event([hit])
        var summary = IndicatorAlertSummary(first)
        for path in ["/bin/a", "/bin/b"] {
            summary.add(try event([hit]) { $0.process.executable?.path = path }, limit: 16)
        }
        let posted = content(.summary(summary))
        XCTAssertEqual(posted.identifier, content(.first(first)).identifier)
        XCTAssertEqual(posted.identifier, "indicator." + first.indicator.id.uuidString)
        XCTAssertEqual(posted.threadIdentifier, posted.identifier)
        XCTAssertEqual(posted.title, "High: Launch job loaded")
        XCTAssertEqual(posted.subtitle, "3 more matches since "
                       + IndicatorAlertContent.clockTime(summary.since, style: .short) + ", from 3 processes")
        XCTAssertEqual(posted.body.components(separatedBy: "\n").count, 2)
        XCTAssertEqual(posted.info.kind, .summary)
        XCTAssertEqual(posted.info.eventID, summary.latest.eventID)

        let one = IndicatorAlertSummary(first)
        XCTAssertTrue(content(.summary(one)).subtitle.hasPrefix("1 more match since "))
        XCTAssertTrue(content(.summary(one)).subtitle.hasSuffix("from 1 process"))
        var many = summary
        many.hasMoreProcesses = true
        XCTAssertTrue(content(.summary(many)).subtitle.hasSuffix("from 3 or more processes"))
    }

    /// The overflow lists three indicators, the rarest first, and how many more. It plays no sound, and its click
    /// opens the first listed indicator's latest event and searches for them all.
    func testTheOverflow() throws {
        let entries = try [("Mach-O written", 24), ("Launch job loaded", 2), ("Dylib inserted", 1),
                           ("New executable", 30), ("Plist modified", 40)].map { name, count in
            let latest = try event([alertHit(name, .medium)])
            return IndicatorAlertOverflow.Entry(indicator: latest.indicator, count: count, latest: latest)
        }
        let overflow = IndicatorAlertOverflow(entries)
        let posted = content(.overflow(overflow))
        XCTAssertEqual(posted.identifier, IndicatorAlertContent.overflowIdentifier)
        XCTAssertEqual(posted.title, "Mac Monitor: 97 more indicator matches")
        XCTAssertEqual(posted.body, "Dylib inserted (1), Launch job loaded (2), Mach-O written (24) "
                       + "and 2 more indicators")
        XCTAssertFalse(posted.playsSound)
        XCTAssertEqual(posted.info.eventID, entries[2].latest.eventID)
        XCTAssertEqual(posted.info.indicators, overflow.entries.map(\.indicator.id))
        let single = content(.overflow(IndicatorAlertOverflow([IndicatorAlertOverflow.Entry(
            indicator: entries[0].indicator, count: 1, latest: entries[0].latest)])))
        XCTAssertEqual(single.title, "Mac Monitor: 1 more indicator match")
        XCTAssertEqual(single.body, "Mach-O written (1)")
    }

    /// Nothing of an exec's command line, arguments, environment, script or `context` reaches a notification: not
    /// its title, subtitle, body or `userInfo`.
    func testNoCommandLineReachesANotification() throws {
        let token = "S3CR3T-TOKEN"
        let leaky = try event { message in
            guard var exec = message.event.exec else { return }
            exec.args = ["/bin/sh", "-c", token]
            exec.env = ["API_KEY=" + token]
            exec.command_line = "/bin/sh -c " + token
            exec.script_content = "echo " + token
            message.event = .exec(exec)
            message.context = "/bin/sh -c " + token
        }
        var summary = IndicatorAlertSummary(leaky)
        summary.add(leaky, limit: 16)
        let entry = IndicatorAlertOverflow.Entry(indicator: leaky.indicator, count: 1, latest: leaky)
        for alert in [IndicatorAlert.first(leaky), .summary(summary), .overflow(IndicatorAlertOverflow([entry]))] {
            let posted = content(alert)
            let text = [posted.title, posted.subtitle, posted.body, "\(posted.info.userInfo)"].joined()
            XCTAssertFalse(text.contains(token), "\(alert)")
        }
        XCTAssertFalse("\(leaky)".contains(token), "The candidate itself holds none of it")
    }

    /// `userInfo` holds the event, the indicator and the kind, and the overflow's indicators: nothing else, and it
    /// reads back.
    func testUserInfoHoldsOnlyIdentities() throws {
        let notice = content(.first(try event()))
        XCTAssertEqual(Set(notice.info.userInfo.keys), ["event", "indicator", "kind"])
        XCTAssertEqual(IndicatorAlertInfo(userInfo: notice.info.userInfo), notice.info)
        let latest = try event([alertHit("Dylib", .medium)])
        let overflow = content(.overflow(IndicatorAlertOverflow([.init(indicator: latest.indicator, count: 2,
                                                                       latest: latest)])))
        XCTAssertEqual(Set(overflow.info.userInfo.keys), ["event", "indicator", "kind", "indicators"])
        XCTAssertEqual(IndicatorAlertInfo(userInfo: overflow.info.userInfo), overflow.info)
        XCTAssertNil(IndicatorAlertInfo(userInfo: ["event": "x", "indicator": UUID().uuidString, "kind": "first"]))
    }

    /// A click's search: an indicator's matches, or every indicator the overflow holds.
    func testTheSearchesAClickRuns() throws {
        let id = UUID()
        let info = IndicatorAlertInfo(kind: .first, eventID: UUID(), indicatorID: id, indicators: [])
        XCTAssertEqual(info.search, #"ANY indicators.id == "\#(id.uuidString)""#)
        let ids = [UUID(), UUID()]
        let overflow = IndicatorAlertInfo(kind: .overflow, eventID: UUID(), indicatorID: ids[0], indicators: ids)
        XCTAssertEqual(overflow.search, #"ANY indicators.id IN {"\#(ids[0].uuidString)", "\#(ids[1].uuidString)"}"#)
        for search in [info.search, overflow.search] {
            XCTAssertNoThrow(try StreamFilter.Predicate(search, for: .search))
        }
    }
}
