//
//  EventHoldScanTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Events held for their scan
/// Pins an event held for its scan (``EventHold``): a written file's close waits, then leaves stamped again with what
/// the scan found, its hit listing the XProtect rule that matched (``IndicatorHit/matched``). An app's exec that runs a
/// script waits for both Launch Services and its script's scan, and scan holds and Launch Services holds never take
/// each other's places.
final class EventHoldScanTests: XCTestCase {
    /// Events the hold sent, in order.
    private let emitted = EmittedEvents()

    /// A close stamped before its scan matches nothing. Once the scan comes it's stamped again, and its hit lists
    /// the rule the scan matched, which Event Facts' Indicators popover shows under Matched.
    func testAHeldCloseListsTheRuleItsScanMatched() throws {
        let rule = ownIndicator("XProtect rule matched", Self.yaraRulePredicate)
        let indicators = CompiledIndicators([rule])
        XCTAssertTrue(indicators.readsYaraScan)
        var close = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_CLOSE", scan: nil))
        var values = MessageValueCache()
        let steps = indicators.stamp(&close, values: &values, deferringSteps: true)
        XCTAssertEqual(close.indicators?.hits, [], "Not scanned yet")
        let ticket = FileScanTicket()
        let hold = EventHold(eventClass: .file, upgrader: nil, maxWait: 5, emit: emitted.append)
        hold.hold(close, stampedWith: indicators, chains: nil, steps: steps, scan: ticket)
        XCTAssertTrue(emitted.all.isEmpty, "Held for its scan")
        ticket.deliver(Self.matchedScan)
        XCTAssertTrue(waitUntil { emitted.all.count == 1 })
        let sent = try JSONDecoder().decode(Message.self, from: try XCTUnwrap(emitted.all.first).json)
        XCTAssertEqual(sent.indicators?.hits.map(\.id), [rule.id])
        XCTAssertEqual(sent.indicators?.hits.first?.matched,
                       [IndicatorMatchedField(field: "event.close.yara_scan.rules", value: .string(Self.matchedRule))])
    }

    /// An app exec that runs a script waits for both answers, whichever comes first, and leaves with both. The scan's
    /// answer is taken on the thread that delivers it, so the exec would be sent by the time `deliver` returns.
    func testAnAppExecWaitsForLaunchServicesAndItsScan() throws {
        let reader = WaitingLaunchServicesReader { pid, _ in self.launchRecord(of: pid) }
        defer { reader.open() }
        let hold = scriptHold(reader)
        let ticket = FileScanTicket()
        hold.hold(try appExec(pid: 606), stampedWith: nil, chains: nil, steps: [], scan: ticket)
        ticket.deliver(Self.matchedScan)
        XCTAssertTrue(emitted.all.isEmpty, "Still waiting for Launch Services")
        reader.open()
        XCTAssertTrue(waitUntil { emitted.all.count == 1 })
        XCTAssertEqual(try sentExecs(), [SentExec(pid: 606, source: .launchServices, rules: [Self.matchedRule])])
    }

    /// Scan holds have places of their own. An exec held for its script's scan doesn't take the one place Launch
    /// Services holds have, so the app exec after it is still looked up.
    func testScanHoldsLeaveLaunchServicesItsPlaces() throws {
        let reader = WaitingLaunchServicesReader { pid, _ in self.launchRecord(of: pid) }
        defer { reader.open() }
        let hold = scriptHold(reader, maxHeld: 1)
        let ticket = FileScanTicket()
        var script = try appExec(pid: 605)
        script.setLaunchedByParent(.shell())
        hold.hold(script, stampedWith: nil, chains: nil, steps: [], scan: ticket)
        hold.hold(try appExec(pid: 606), chains: nil)
        ticket.deliver(Self.matchedScan)
        reader.open()
        XCTAssertTrue(waitUntil { emitted.all.count == 2 })
        XCTAssertEqual(try sentExecs(), [SentExec(pid: 605, source: .unixParent, rules: [Self.matchedRule]),
                                         SentExec(pid: 606, source: .launchServices, rules: nil)])
    }

    /// Launch Services holds have places of their own too. Past them, an app exec that runs a script is still held for
    /// its scan, and leaves with its scan and the parent it has.
    func testLaunchServicesHoldsLeaveScansTheirPlaces() throws {
        let reader = WaitingLaunchServicesReader { pid, _ in self.launchRecord(of: pid) }
        defer { reader.open() }
        let hold = scriptHold(reader, maxHeld: 1)
        let ticket = FileScanTicket()
        hold.hold(try appExec(pid: 605), chains: nil)
        hold.hold(try appExec(pid: 606), stampedWith: nil, chains: nil, steps: [], scan: ticket)
        ticket.deliver(Self.matchedScan)
        XCTAssertTrue(emitted.all.isEmpty, "Behind the app exec Launch Services hasn't answered for")
        reader.open()
        XCTAssertTrue(waitUntil { emitted.all.count == 2 })
        XCTAssertEqual(try sentExecs(), [SentExec(pid: 605, source: .launchServices, rules: nil),
                                         SentExec(pid: 606, source: .launchdJob, rules: [Self.matchedRule])])
    }

    /// Past the scan holds' places, an exec's scan leaves as busy. An app exec past them is still held for Launch
    /// Services, and leaves with its parent and a busy scan.
    func testScanHoldsPastTheirPlacesLeaveBusy() throws {
        let reader = WaitingLaunchServicesReader { pid, _ in self.launchRecord(of: pid) }
        defer { reader.open() }
        let hold = scriptHold(reader, maxScanHeld: 1)
        let (first, second, third) = (FileScanTicket(), FileScanTicket(), FileScanTicket())
        var script = try appExec(pid: 604)
        script.setLaunchedByParent(.shell())
        hold.hold(script, stampedWith: nil, chains: nil, steps: [], scan: first)
        var other = try appExec(pid: 605)
        other.setLaunchedByParent(.shell())
        hold.hold(other, stampedWith: nil, chains: nil, steps: [], scan: second)
        hold.hold(try appExec(pid: 606), stampedWith: nil, chains: nil, steps: [], scan: third)
        [first, second, third].forEach { $0.deliver(Self.matchedScan) }
        reader.open()
        XCTAssertTrue(waitUntil { emitted.all.count == 3 })
        XCTAssertEqual(try sentExecs(), [SentExec(pid: 604, source: .unixParent, rules: [Self.matchedRule]),
                                         SentExec(pid: 605, source: .unixParent, rules: []),
                                         SentExec(pid: 606, source: .launchServices, rules: [])])
        XCTAssertEqual(try sent().map(\.yara_scan?.status), [YaraScan.scanned, YaraScan.busy, YaraScan.busy])
    }

    /// An exec whose answers don't come in time leaves with the parent it has and a busy scan.
    func testAnExecWhoseAnswersDontComeLeavesBusy() throws {
        let reader = WaitingLaunchServicesReader()
        defer { reader.open() }
        let hold = scriptHold(reader, maxWait: 0.05)
        hold.hold(try appExec(pid: 606), stampedWith: nil, chains: nil, steps: [], scan: FileScanTicket())
        XCTAssertTrue(waitUntil { emitted.all.count == 1 })
        XCTAssertEqual(try sentExecs(), [SentExec(pid: 606, source: .launchdJob, rules: [])])
        XCTAssertEqual(try sent().map(\.yara_scan?.status), [YaraScan.busy])
    }

    /// A held event is given up at user initiated, the QoS a stream's batches go at, so the half-second cap holds on
    /// a busy Mac whose utility threads wait. Here the close is held from a utility thread, as the scanner's answers
    /// come, and its scan never answers.
    func testAHoldIsGivenUpAtUserInitiated() throws {
        let close = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_CLOSE", scan: nil))
        let qos = Recorded<DispatchQoS.QoSClass?>()
        let hold = EventHold(eventClass: .file, upgrader: nil, maxWait: 0.01) { event in
            qos.append(DispatchQoS.QoSClass(rawValue: qos_class_self()))
            self.emitted.append(event)
        }
        DispatchQueue.global(qos: .utility).async {
            hold.hold(close, chains: nil, scan: FileScanTicket())
        }
        XCTAssertTrue(waitUntil { emitted.all.count == 1 })
        XCTAssertEqual(qos.all, [.userInitiated])
        let sent = try JSONDecoder().decode(Message.self, from: try XCTUnwrap(emitted.all.first).json)
        guard case .close(let event) = sent.event else { return XCTFail("Not the close") }
        XCTAssertEqual(event.yara_scan?.status, YaraScan.busy)
    }

    // MARK: Helpers

    /// The process lane's hold, sending into ``emitted``, with an upgrader reading at once, 10 and 20 ms later.
    ///
    /// - Parameters:
    ///   - reader: Launch Services.
    ///   - maxHeld: The most execs held for Launch Services.
    ///   - maxScanHeld: The most execs held for their scans.
    ///   - maxWait: The longest an exec is held.
    /// - Returns: The hold.
    private func scriptHold(_ reader: LaunchServicesReading, maxHeld: Int = 64, maxScanHeld: Int = 64,
                            maxWait: TimeInterval = 5) -> EventHold {
        processHold(reader, delays: [0, 0.01, 0.02], maxHeld: maxHeld, maxScanHeld: maxScanHeld, maxWait: maxWait,
                    emitted: emitted)
    }

    /// An app's exec as the lane builds it: launchd started its job, so it's held for Launch Services.
    ///
    /// - Parameter pid: The app's pid.
    /// - Returns: The exec.
    /// - Throws: The error reading the exec's record.
    private func appExec(pid: Int32) throws -> Message {
        appExec(try importRecord(try esloggerExec(parent: (1, 1))), pid: pid)
    }

    /// An exec the hold sent: its pid, how its launched-by parent was found, and the rules its scan matched.
    private struct SentExec: Equatable {
        let pid: Int32
        let source: LaunchedByParent.Source?
        let rules: [String]?
    }

    /// The execs the hold sent, in order.
    ///
    /// - Returns: Each exec's pid, launched-by parent's source and the rules its scan matched.
    /// - Throws: The error decoding one.
    private func sentExecs() throws -> [SentExec] {
        try sent().map { exec in
            SentExec(pid: exec.target.pid, source: exec.launched_by_parent?.source, rules: exec.yara_scan?.rules)
        }
    }

    /// The execs the hold sent, in order, as Mac Monitor decodes them.
    ///
    /// - Returns: The execs.
    /// - Throws: The error decoding one.
    private func sent() throws -> [ProcessExecEvent] {
        try emitted.all.compactMap { event in
            guard case .exec(let exec) = try JSONDecoder().decode(Message.self, from: event.json).event else {
                return nil
            }
            return exec
        }
    }
}
