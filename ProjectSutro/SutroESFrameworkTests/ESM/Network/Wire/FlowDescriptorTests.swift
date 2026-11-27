//
//  FlowDescriptorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Descriptors
/// Pins what's read from a descriptor: every recorded update's fields are the reference decoder's, and an address
/// is written so it matches the same address in any list.
final class FlowDescriptorTests: XCTestCase {
    /// Every recorded descriptor's fields equal the reference decoder's.
    func testEveryRecordedDescriptorReadsAsDecoded() throws {
        for darwin in [22, 27] {
            for (message, provider, offset) in try descriptorMessages(darwin: darwin) {
                try message.bytes.withUnsafeBytes { bytes in
                    let layout = try XCTUnwrap(DescriptorLayout.detect(provider.kind, bytes, at: offset))
                    let descriptor = try XCTUnwrap(FlowDescriptor(bytes, at: offset, layout: layout))
                    let read: [String: String] = [
                        "upid": "\(descriptor.upid)", "pid": "\(descriptor.pid)", "epid": "\(descriptor.epid)",
                        "start_timestamp": "\(descriptor.start)", "pname": descriptor.processName(),
                        "ifnet_properties": "\(descriptor.ifnetProperties)", "local": text(descriptor.local),
                        "remote": text(descriptor.remote)
                    ].merging(descriptor.state.map { ["state": "\($0)"] } ?? [:]) { first, _ in first }
                    for (key, value) in read where message.decoded[key] != nil {
                        XCTAssertEqual(value, message.decoded[key], "\(key) of \(message.decoded)")
                    }
                }
            }
        }
    }

    /// An IPv4-mapped address is written as IPv4, a scope never is, and loopback is told apart from anything else.
    func testAddressesAreWrittenToMatch() {
        let address = { (text: String, port: UInt16) in
            NStatMessageBuilder.sockaddr(.init(address: text, port: port)).withUnsafeBytes { FlowAddress($0, at: 0) }
        }
        XCTAssertEqual(address("::ffff:198.35.26.224", 443).text(), "198.35.26.224")
        XCTAssertEqual(address("2620:0:862:ed1a::1", 443).text(), "2620:0:862:ed1a::1")
        XCTAssertEqual(address("198.35.26.224", 443).endpoint(), FlowEndpoint(address: "198.35.26.224", port: 443))
        XCTAssertEqual([address("127.0.0.1", 80), address("127.8.0.1", 80), address("::1", 80),
                        address("::ffff:127.0.0.1", 80)].map(\.isLoopback), [true, true, true, true])
        XCTAssertEqual([address("128.0.0.1", 80), address("::2", 80), address("::ffff:10.0.0.1", 80)].map(\.isLoopback),
                       [false, false, false])
        XCTAssertFalse(address("0.0.0.0", 0).isKnown)
        XCTAssertNil(address("0.0.0.0", 0).text())
        XCTAssertTrue(address("0.0.0.0", 5353).isKnown)
        XCTAssertFalse(FlowAddress.none.isKnown)
    }

    /// An address as the reference decoder writes it: IPv6 in brackets, then the port, and `-` for none.
    ///
    /// - Parameter address: The address.
    /// - Returns: The text.
    private func text(_ address: FlowAddress) -> String {
        guard address.family != 0 else { return "-" }
        let isIPv6 = Int32(address.family) == AF_INET6
        let text = address.text() ?? (isIPv6 ? "::" : "0.0.0.0")
        return isIPv6 ? "[\(text)]:\(address.port)" : "\(text):\(address.port)"
    }
}
