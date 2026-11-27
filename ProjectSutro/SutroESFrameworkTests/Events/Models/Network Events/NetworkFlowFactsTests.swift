//
//  NetworkFlowFactsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A flow's facts
/// Pins what Event Facts shows of a stored network flow: its rows and their order, each value as it's written, the
/// rows a flow without a value leaves out, and what its Details box adds.
final class NetworkFlowFactsTests: XCTestCase {
    /// When the synthetic flows were seen, as a date.
    private let seen = Date(timeIntervalSince1970: TimeInterval(SyntheticFlows.wall) / 1e9)

    /// - Parameter message: A flow's message.
    /// - Returns: Its facts, read from the event the store keeps.
    private func facts(_ message: Message) throws -> NetworkFlowFacts {
        try XCTUnwrap(withStoredEvent(message) { NetworkFlowFacts(message: $0) })
    }

    /// - Parameter facts: A flow's facts.
    /// - Returns: Each row's fact names.
    private func names(_ facts: NetworkFlowFacts) -> [[String]] {
        facts.rows.map { $0.map(\.name) }
    }

    /// - Parameters:
    ///   - facts: A flow's facts.
    ///   - name: A fact's name.
    /// - Returns: The fact, if a row has it.
    private func fact(_ facts: NetworkFlowFacts, _ name: String) -> EventFact? {
        facts.rows.joined().first { $0.name == name }
    }

    /// - Parameters:
    ///   - kind: Opened or closed.
    ///   - change: Changes the flow before it's stored.
    /// - Returns: The flow's message.
    private func message(_ kind: FlowRecord.Kind, _ change: (inout NetworkFlowEvent) -> Void) -> Message {
        var message = SyntheticFlows.message(SyntheticFlows.record(kind))
        var flow = message.event.networkFlow!
        change(&flow)
        flow.enrich()
        message.event = kind == .opened ? .new_flow(flow) : .flow_closed(flow)
        return message
    }

    /// A delegated flow that closed with its counts has every row, in order, each value as Event Facts writes it.
    func testAFullClosedFlowHasEveryRow() throws {
        let delegate = SyntheticFlows.process(pid: 249, path: "/usr/sbin/mDNSResponder")
        let record = SyntheticFlows.record(.closed, process: delegate, sourceApp: SyntheticFlows.process(),
                                           start: SyntheticFlows.wall - 4_200_000_000)
        let facts = try facts(SyntheticFlows.message(record))
        XCTAssertEqual(names(facts), [["Direction", "Protocol"], ["Remote host"], ["Local endpoint"], ["URL"],
                                      ["Bytes in", "Bytes out", "Open for"], ["On behalf of"]])
        XCTAssertEqual(facts.rows.joined().map(\.values), [
            ["outbound"], ["TCP", "IPv4"], ["en.wikipedia.org", "198.35.26.224:443"], ["192.168.64.2:49310"],
            ["https://en.wikipedia.org/wiki/Endpoint_security"], ["36,385"], ["3,059"], ["4.20s"],
            ["nscurl", "com.apple.nscurl"],
        ])
        XCTAssertEqual(fact(facts, "URL")?.isLong, true)
        XCTAssertEqual(facts.rows.joined().filter(\.isLong).map(\.name), ["URL"])
        XCTAssertEqual(fact(facts, "Bytes in")?.help, "36.4 KB")
        XCTAssertEqual(fact(facts, "Bytes out")?.help, "3.1 KB")
        XCTAssertEqual(fact(facts, "On behalf of")?.help, "/usr/bin/nscurl")
    }

    /// A new flow has the same rows without its bytes and how long it was open.
    func testANewFlowHasNoCounts() throws {
        let facts = try facts(SyntheticFlows.message(SyntheticFlows.record(.opened)))
        XCTAssertEqual(names(facts), [["Direction", "Protocol"], ["Remote host"], ["Local endpoint"], ["URL"]])
    }

    /// A flow without a direction, hostname, local endpoint or URL leaves their rows out, and its remote host is its
    /// address and port alone.
    func testAMinimalFlowLeavesRowsOut() throws {
        let opened = try facts(SyntheticFlows.message(SyntheticFlows.record(.opened, minimal: true)))
        XCTAssertEqual(names(opened), [["Protocol"], ["Remote host"]])
        XCTAssertEqual(fact(opened, "Remote host")?.values, ["198.35.26.224:443"])
        let closed = try facts(SyntheticFlows.message(SyntheticFlows.record(.closed, minimal: true)))
        XCTAssertEqual(names(closed), [["Protocol"], ["Remote host"], ["Bytes in", "Bytes out", "Open for"]])
    }

    /// A closed flow whose final counts were lost has how long it was open alone, and one that closed before its
    /// socket was made, by a clock that stepped back, has no row of counts at all.
    func testCountsAndOpenForAreLeftOutWhenAbsent() throws {
        let lost = try facts(SyntheticFlows.message(SyntheticFlows.record(.closed, counted: false)))
        XCTAssertEqual(names(lost).last, ["Open for"])
        XCTAssertEqual(fact(lost, "Open for")?.values, ["0.00s"])
        let stepped = SyntheticFlows.record(.closed, counted: false, start: SyntheticFlows.wall + 1_000_000_000)
        XCTAssertEqual(names(try facts(SyntheticFlows.message(stepped))),
                       [["Direction", "Protocol"], ["Remote host"], ["Local endpoint"], ["URL"]])
    }

    /// How long a closed flow was open is its close's time less its socket's start, as Event Facts writes an age.
    func testOpenFor() throws {
        let cases: [(Int64, String)] = [(3_500_000, "0.00s"), (4_200_000_000, "4.20s"), (59_996_000_000, "59.99s"),
                                        (240_000_000_000, "4min"), (90_000_000_000_000, "1 day")]
        for (before, text) in cases {
            let record = SyntheticFlows.record(.closed, start: SyntheticFlows.wall - before)
            XCTAssertEqual(fact(try facts(SyntheticFlows.message(record)), "Open for")?.values, [text], "\(before)")
        }
    }

    /// TCP and UDP over IPv4 and IPv6, from the socket's names, and a name Mac Monitor doesn't shorten as it is.
    func testProtocolPair() {
        let cases: [((String, String), [String])] = [
            (("IPPROTO_TCP", "AF_INET"), ["TCP", "IPv4"]), (("IPPROTO_UDP", "AF_INET6"), ["UDP", "IPv6"]),
            (("IPPROTO_ICMP", "AF_INET"), ["ICMP", "IPv4"]),
            (("UNKNOWN(99)", "UNKNOWN(7)"), ["UNKNOWN(99)", "UNKNOWN(7)"]),
        ]
        for ((proto, family), pair) in cases {
            XCTAssertEqual(NetworkFlowFacts.protocolPair(protocol: proto, family: family), pair, proto)
        }
    }

    /// A QUIC flow over IPv6 is UDP over IPv6, its address bracketed as a URL writes one.
    func testUDPOverIPv6() throws {
        let facts = try facts(message(.closed) { flow in
            (flow.socket_family, flow.socket_type, flow.socket_protocol) = (AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            flow.remote_endpoint = FlowEndpoint(address: "2001:db8::1", port: 443)
            flow.local_endpoint = FlowEndpoint(address: "2001:db8::2", port: 51_000)
        })
        XCTAssertEqual(fact(facts, "Protocol")?.values, ["UDP", "IPv6"])
        XCTAssertEqual(fact(facts, "Remote host")?.values, ["en.wikipedia.org", "[2001:db8::1]:443"])
        XCTAssertEqual(fact(facts, "Local endpoint")?.values, ["[2001:db8::2]:51000"])
    }

    /// A hostname that's the remote address itself isn't shown twice, and an empty one isn't shown.
    func testRemoteHostIsNotRepeated() throws {
        for hostname in ["198.35.26.224", ""] {
            let facts = try facts(message(.opened) { $0.remote_hostname = hostname })
            XCTAssertEqual(fact(facts, "Remote host")?.values, ["198.35.26.224:443"], hostname)
        }
    }

    /// The first-party site has its own row after the URL, but only when the remote host isn't that site or a host in
    /// it, which the Remote host row already shows.
    func testFirstPartySite() throws {
        let cases: [(hostname: String?, site: String?, shown: Bool)] = [
            ("upload.wikimedia.org", "wikipedia.org", true), ("notwikipedia.org", "wikipedia.org", true),
            (nil, "wikipedia.org", true), ("en.wikipedia.org", "wikipedia.org", false),
            ("wikipedia.org", "wikipedia.org", false), ("EN.Wikipedia.org", "wikipedia.org", false),
            ("upload.wikimedia.org", nil, false), ("upload.wikimedia.org", "", false),
        ]
        for (hostname, site, shown) in cases {
            let facts = try facts(message(.opened) { ($0.remote_hostname, $0.first_party_site) = (hostname, site) })
            let label = "\(hostname ?? "nil") on \(site ?? "nil")"
            XCTAssertEqual(fact(facts, "First-party site")?.values, shown ? ["wikipedia.org"] : nil, label)
            XCTAssertEqual(names(facts).last, shown ? ["First-party site"] : ["URL"], label)
        }
    }

    /// Byte counts are whole numbers with a comma every three digits, whatever this Mac's locale, and a count of a
    /// thousand or more has its size in decimal units on hover.
    func testByteCounts() throws {
        let cases: [(Int64, String)] = [(0, "0"), (999, "999"), (36_948, "36,948"), (1_234_567_890, "1,234,567,890")]
        for (bytes, text) in cases { XCTAssertEqual(NetworkFlowFacts.count(bytes), text) }
        let facts = try facts(message(.closed) { ($0.bytes_inbound_count, $0.bytes_outbound_count) = (512, 0) })
        XCTAssertEqual(fact(facts, "Bytes in")?.values, ["512"])
        XCTAssertNil(fact(facts, "Bytes in")?.help)
        XCTAssertEqual(fact(facts, "Bytes out")?.values, ["0"])
    }

    /// The app a delegated socket acts for is named by its executable and signing ID, either alone when the other
    /// isn't known or is the same, and by its pid when neither is known.
    func testOnBehalfOf() throws {
        let cases: [(FlowProcess, [String], String?)] = [
            (SyntheticFlows.process(pid: 661, path: "/Applications/Safari.app/Contents/MacOS/Safari",
                                    signingID: "com.apple.Safari"),
             ["Safari", "com.apple.Safari"], "/Applications/Safari.app/Contents/MacOS/Safari"),
            (SyntheticFlows.process(pid: 661, signingID: ""), ["nscurl"], "/usr/bin/nscurl"),
            /// A linker-signed tool's signing ID is its file name.
            (SyntheticFlows.process(pid: 661, path: "/usr/local/bin/fetch", signingID: "fetch"), ["fetch"],
             "/usr/local/bin/fetch"),
            (SyntheticFlows.process(pid: 661, state: .reaped), ["PID 661"], nil),
        ]
        for (app, values, help) in cases {
            let record = SyntheticFlows.record(.opened, sourceApp: app)
            let onBehalf = fact(try facts(SyntheticFlows.message(record)), "On behalf of")
            XCTAssertEqual(onBehalf?.values, values)
            XCTAssertEqual(onBehalf?.help, help)
        }
    }

    /// The Details box gets the flow's identifier and when its socket was made, shown as Event Facts shows a time,
    /// with the record's time on hover.
    func testDetails() throws {
        for kind in [FlowRecord.Kind.opened, .closed] {
            let facts = try facts(SyntheticFlows.message(SyntheticFlows.record(kind)))
            XCTAssertEqual(facts.details.map(\.name), ["Flow ID", "Opened"])
            XCTAssertEqual(facts.details.map(\.values), [
                [SyntheticFlows.identifier.uuidString], [eventLocalTime(seen.addingTimeInterval(-0.0035))],
            ])
            XCTAssertEqual(facts.details.map(\.help), [nil, "2026-10-05T12:00:00.119956789Z"])
        }
        let shape = #"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \S+$"#
        XCTAssertNotNil(eventLocalTime(seen).range(of: shape, options: .regularExpression), eventLocalTime(seen))
    }

    /// An Endpoint Security event has no flow facts.
    func testAnEndpointSecurityEventHasNone() throws {
        let exit = try exitMessage(of: try shell())
        XCTAssertNil(withStoredEvent(exit) { NetworkFlowFacts(message: $0) })
    }
}
