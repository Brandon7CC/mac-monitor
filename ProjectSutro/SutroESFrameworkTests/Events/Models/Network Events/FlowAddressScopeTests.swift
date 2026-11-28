//
//  FlowAddressScopeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - An address's scope
/// Pins each scope at the edges of its blocks, for IPv4, IPv6, and IPv4 carried in IPv6, and that a flow's record
/// has its remote address's.
final class FlowAddressScopeTests: XCTestCase {
    /// Every block's prefix is an address, and its length fits the address.
    func testEveryBlockIsAnAddress() {
        for block in FlowAddressScope.ipv4 + FlowAddressScope.ipv6 + FlowAddressScope.carryingIPv4 {
            XCTAssertTrue([4, 16].contains(block.bytes.count), "\(block)")
            XCTAssertLessThanOrEqual(block.length, block.bytes.count * 8, "\(block)")
        }
    }

    /// IPv4 addresses on each side of each block's edges.
    func testIPv4() {
        assertScopes([
            ("8.8.8.8", .public), ("0.0.0.0", .reserved), ("0.1.2.3", .reserved), ("10.0.0.0", .private),
            ("10.255.255.255", .private),
            ("11.0.0.0", .public), ("100.63.255.255", .public), ("100.64.0.0", .shared),
            ("100.127.255.255", .shared), ("100.128.0.0", .public), ("127.0.0.1", .loopback),
            ("169.254.169.254", .linkLocal), ("172.15.255.255", .public), ("172.16.0.1", .private),
            ("172.31.255.255", .private), ("172.32.0.0", .public), ("192.0.0.8", .reserved), ("192.0.0.9", .public),
            ("192.0.0.10", .public), ("192.0.0.11", .reserved), ("192.0.0.255", .reserved), ("192.0.2.1", .reserved),
            ("192.88.99.1", .reserved),
            ("192.168.64.1", .private), ("198.17.255.255", .public), ("198.18.0.1", .reserved),
            ("198.19.255.255", .reserved), ("198.20.0.0", .public), ("198.51.100.7", .reserved),
            ("203.0.113.9", .reserved), ("223.255.255.255", .public), ("224.0.0.251", .multicast),
            ("239.255.255.250", .multicast), ("240.0.0.1", .reserved), ("255.255.255.255", .reserved),
        ])
    }

    /// IPv6 addresses on each side of each block's edges, and IPv4 addresses mapped into IPv6 or NAT64's well-known
    /// prefix. Only 64:ff9b::/96 is unwrapped, not the local-use 64:ff9b:1::/48.
    func testIPv6() {
        assertScopes([
            ("2606:4700::1111", .public), ("2001:db8::1", .reserved), ("2001:2::1", .reserved),
            ("2001:3::1", .public), ("3fff::1", .reserved), ("3fff:1000::", .public), ("::1", .loopback),
            ("::", .reserved), ("fd7a:115c:a1e0::1", .private), ("fc00::1", .private), ("fe80::1", .linkLocal),
            ("febf::1", .linkLocal), ("fec0::1", .reserved), ("ff02::fb", .multicast), ("1fff::1", .reserved),
            ("4000::1", .reserved), ("::ffff:10.0.0.1", .private), ("::ffff:8.8.8.8", .public),
            ("64:ff9b::8.8.8.8", .public), ("64:ff9b::192.168.1.1", .private), ("64:ff9b:1::1", .reserved),
            ("fbff:ffff:ffff:ffff::", .reserved), ("fe00::1", .reserved), ("fe7f:ffff::1", .reserved),
            ("::fffe:a00:1", .reserved), ("64:ff9b::1:a00:1", .reserved), ("1fff:ffff::", .reserved),
        ])
    }

    /// 2001::/23, IETF protocol assignments, is reserved, except the blocks in it the registry calls reachable.
    func testIETFProtocolAssignments() {
        assertScopes([
            ("2001::1", .public), ("2001:0:ffff::1", .public), ("2001:1::1", .public), ("2001:1::3", .public),
            ("2001:1::4", .reserved), ("2001:2::1", .reserved), ("2001:3::1", .public), ("2001:4::1", .reserved),
            ("2001:4:112::1", .public), ("2001:10::1", .reserved), ("2001:20::1", .public),
            ("2001:2f:ffff::1", .public), ("2001:30::1", .public), ("2001:40::1", .reserved),
            ("2001:1ff:ffff::1", .reserved), ("2001:200::1", .public), ("2001:db8::1", .reserved),
        ])
    }

    /// Text that isn't an address has no scope.
    func testNotAnAddress() {
        for text in ["", "example.com", "192.0.2", "2001:db8::g"] {
            XCTAssertNil(FlowAddressScope(address: text), text)
        }
    }

    /// A flow's record has its remote address's scope, on its new_flow and its flow_closed alike.
    func testAFlowsRecordHasItsScope() throws {
        for kind in [FlowRecord.Kind.opened, .closed] {
            let flow = try XCTUnwrap(SyntheticFlows.message(SyntheticFlows.record(kind)).event.networkFlow)
            XCTAssertEqual(flow.remote_address_scope, .public)
        }
    }

    /// Checks each address's scope.
    ///
    /// - Parameter expected: Each address, and its scope.
    private func assertScopes(_ expected: [(String, FlowAddressScope)], line: UInt = #line) {
        for (address, scope) in expected {
            XCTAssertEqual(FlowAddressScope(address: address), scope, address, line: line)
        }
    }
}
