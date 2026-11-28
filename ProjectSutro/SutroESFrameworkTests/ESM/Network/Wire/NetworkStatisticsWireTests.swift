//
//  NetworkStatisticsWireTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The wire
/// Pins how the client walks the kernel's messages and writes its own requests: every recorded message on macOS
/// 13.6 and 27.2 walks, an error echoes the request it answers, and each request is byte for byte what the probes
/// sent.
final class NetworkStatisticsWireTests: XCTestCase {
    /// Every recorded message walks as one whole message of its decoded type.
    func testEveryRecordedMessageWalks() throws {
        for darwin in [22, 27] {
            for message in try nstatMessages(darwin: darwin) {
                var walked: [NStat.Header] = []
                let whole = message.bytes.withUnsafeBytes { NStat.forEachMessage(in: $0) { header, _ in
                    walked.append(header)
                } }
                XCTAssertTrue(whole)
                XCTAssertEqual(walked.map { UInt64($0.type) }, [message.number("type")])
                XCTAssertEqual(walked.first.map { Int($0.length) }, message.bytes.count)
            }
        }
    }

    /// Darwin 25 and later pack several messages into one datagram. A length that runs past the datagram, a length
    /// under a header's, or bytes left over stop the walk, and it says so.
    func testADatagramHoldsSeveralMessages() {
        let build = NStatMessageBuilder()
        let packed = build.added(1, .tcpUserland) + build.removed(1) + build.added(2, .udpSubflow)
        XCTAssertEqual(walk(packed), [10_001, 10_002, 10_001])
        XCTAssertTrue(NStat.forEachMessage(in: UnsafeRawBufferPointer(start: nil, count: 0)) { _, _ in })
        for broken in [Array(packed.dropLast()), packed + [0, 0, 0], [UInt8](repeating: 0, count: 32)] {
            broken.withUnsafeBytes { XCTAssertFalse(NStat.forEachMessage(in: $0) { _, _ in }) }
        }
        XCTAssertEqual(walk(Array(packed.dropLast())), [10_001, 10_002], "The whole messages before the cut walk")
    }

    /// An error is 24 bytes and the request it answers: 48 for a query, 80 for an add. Its errno is read at 16,
    /// and its context says which request.
    func testAnErrorEchoesItsRequest() throws {
        let errors = try [22, 27].flatMap { try nstatMessages(darwin: $0) }.filter { $0.number("type") == 1 }
        XCTAssertEqual(Set(errors.map(\.bytes.count)), [48, 80])
        for error in errors {
            error.bytes.withUnsafeBytes { bytes in
                XCTAssertEqual(UInt64(bytes.integer(at: NStat.Offset.error, as: UInt32.self)), error.number("error"))
                XCTAssertEqual(NStat.Header(bytes).context, error.number("ctx"))
            }
        }
        let echoed = NStatMessageBuilder().error(.add(.udpSubflow), EPERM, echoing: [UInt8](repeating: 1, count: 56))
        XCTAssertEqual(walk(echoed), [1])
        XCTAssertEqual(echoed.count, 80)
    }

    /// Each request is byte for byte the probes' own.
    func testRequestsAreTheProbesBytes() throws {
        let requests = try [22, 27].flatMap { try nstatMessages(darwin: $0) }.filter { $0.direction == "out" }
        XCTAssertEqual(requests.count, 40)
        for request in requests {
            let written: [UInt8] = request.bytes.withUnsafeBytes { bytes in
                let context = NStat.Header(bytes).context
                if NStat.Header(bytes).type == NStat.MessageType.addAllSources.rawValue {
                    return NStat.addAll(bytes.integer(at: 32), filter: bytes.integer(at: 16),
                                        events: bytes.integer(at: 24), context: context) { Array($0) }
                }
                return NStat.getUpdate(bytes.integer(at: 16), context: context, flags: NStat.Header(bytes).flags) {
                    Array($0)
                }
            }
            XCTAssertEqual(written, request.bytes)
        }
    }

    /// What the client asks for: the domain item from every provider, the NECP parameters from the userland ones,
    /// and never the connection provider. Each provider but the UDP subflow accepts every interface but loopback,
    /// so the kernel holds back a loopback source's updates. Those are XNU's interface bits, 17 through Darwin 23
    /// and 19 from Darwin 24, less loopback (0x2) and the local and non-local bits (0x800, 0x1000) a loopback source
    /// has too. Unknown (0x1) stays, for a socket that hasn't connected yet.
    func testEachProviderAsksForItsItems() {
        XCTAssertEqual(NStat.Provider.allCases.map(\.rawValue), [2, 3, 4, 5, 8, 10])
        XCTAssertEqual(NStat.Provider.allCases.filter(\.carriesParameters), [.tcpUserland, .udpUserland, .quicUserland])
        XCTAssertEqual(NStat.Provider.quicUserland.kind, .tcp)
        for darwin in [22, 23, 24, 25, 27] {
            let interfaces: UInt64 = darwin < 24 ? 0x1_E7FD : 0x7_E7FD
            for provider in NStat.Provider.allCases {
                let items: UInt64 = provider.carriesParameters ? 1 << 41 | 1 << 42 : 1 << 41
                let expected = items | (provider == .udpSubflow ? 0 : interfaces)
                XCTAssertEqual(String(provider.filter(darwin: darwin), radix: 16), String(expected, radix: 16),
                               "\(provider) on Darwin \(darwin)")
            }
        }
    }

    /// A reply's context says which request it answers, and a source reference is never taken for another kind.
    func testContextsTellTheRequestsApart() {
        let requests: [NStat.Request] = [.mode, .add(.tcpKernel), .add(.udpSubflow), .query(1), .query(258),
                                         .check(258)]
        XCTAssertEqual(requests.map { NStat.Request(context: $0.context) }, requests)
        XCTAssertEqual(Set(requests.map(\.context)).count, requests.count)
        XCTAssertNil(NStat.Request(context: 0x7100_0000_0000_0009), "Not a provider the client adds")
        XCTAssertEqual(NStat.Request.mode.context, 0x7000_0000_0000_0000, "The probes' context for it")
    }

    /// The types of the messages a datagram holds.
    ///
    /// - Parameter datagram: The datagram.
    /// - Returns: Each message's type.
    private func walk(_ datagram: [UInt8]) -> [UInt32] {
        var types: [UInt32] = []
        datagram.withUnsafeBytes { _ = NStat.forEachMessage(in: $0) { header, _ in types.append(header.type) } }
        return types
    }
}
