//
//  DescriptorEncodingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Descriptor encodings
/// Pins the fallback layouts read from the NetworkStatistics framework's instance variable encodings: the recorded
/// encodings of macOS 13.6 and 27.2 lay out as the known layouts, and this Mac's framework agrees with one.
final class DescriptorEncodingTests: XCTestCase {
    /// Each recorded encoding has the size the kernel's messages showed.
    func testRecordedEncodingsHaveTheirSizes() throws {
        let sizes = ["darwin22-tcp": 336, "darwin22-udp": 272, "darwin22-counts": 112, "darwin27-tcp": 360,
                     "darwin27-udp": 280, "darwin27-counts": 112, "darwin27-conn-details": 688]
        for (name, size) in sizes {
            XCTAssertEqual(DescriptorEncoding.fields(of: try encoding(name))?.size, size, name)
        }
        let counts = try XCTUnwrap(DescriptorEncoding.fields(of: try encoding("darwin27-counts")))
        XCTAssertEqual(counts.fields["nstat_rxbytes"]?.offset, 8)
        XCTAssertEqual(counts.fields["nstat_txbytes"]?.offset, 24)
    }

    /// Each recorded descriptor encoding lays out as its known layout, bit-fields, unions and all.
    func testRecordedEncodingsAreTheKnownLayouts() throws {
        let expected: [(String, DescriptorLayout.Kind, DescriptorLayout)] = [
            ("darwin22-tcp", .tcp, .tcp22), ("darwin22-udp", .udp, .udp22), ("darwin27-tcp", .tcp, .tcp27),
            ("darwin27-udp", .udp, .udp23)
        ]
        for (name, kind, layout) in expected {
            XCTAssertEqual(DescriptorEncoding.layout(kind, encoding: try encoding(name)), layout, name)
        }
    }

    /// An encoding that doesn't parse, lacks a field the client reads, or has one narrower than what's read of it,
    /// gives no layout.
    func testABrokenEncodingGivesNoLayout() throws {
        let tcp = try encoding("darwin27-tcp")
        let renamed = tcp.replacingOccurrences(of: "\"pname\"", with: "\"name\"")
        for broken in [String(tcp.dropLast()), renamed, "{x=\"a\"Z}", "[4", "{s=\"a\"b}"] {
            XCTAssertNil(DescriptorEncoding.layout(.tcp, encoding: broken), broken)
        }
        XCTAssertNil(DescriptorEncoding.layout(.tcp, encoding: try encoding("darwin27-udp")), "UDP has no state")
        for (field, narrow) in [("\"pname\"[64c]", "\"pname\"[32c]"), ("\"pid\"I", "\"pid\"S")] {
            let narrowed = tcp.replacingOccurrences(of: field, with: narrow)
            XCTAssertNotEqual(narrowed, tcp)
            XCTAssertNil(DescriptorEncoding.layout(.tcp, encoding: narrowed), "A field narrower than what's read")
        }
        let pointers = try XCTUnwrap(DescriptorEncoding.fields(of: "{p=\"a\"C\"b\"^v\"c\"[3s]\"e\"C}"))
        XCTAssertEqual(pointers.size, 24)
        XCTAssertEqual(pointers.fields["e"]?.offset, 22)
    }

    /// This Mac's framework, read through the Objective-C runtime, has one of the known layouts.
    func testThisMacsFrameworkHasAKnownLayout() throws {
        for kind in DescriptorLayout.Kind.allCases {
            let layout = try XCTUnwrap(DescriptorEncoding.layout(of: kind), "NetworkStatistics.framework is readable")
            XCTAssertTrue(DescriptorLayout.known(kind).contains(layout), "\(layout)")
        }
    }

    /// A recorded encoding.
    ///
    /// - Parameter name: Its name after `nstat-encoding-`.
    /// - Returns: The encoding.
    /// - Throws: An `XCTest` failure when it's missing.
    private func encoding(_ name: String) throws -> String {
        String(decoding: try fixture("nstat-encoding-\(name).txt"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
