//
//  DescriptorLayoutTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Descriptor layouts
/// Pins how a descriptor's layout is picked: by what fits the message, largest first, anchored on the domain item,
/// and from the running framework's encoding when no known layout fits.
final class DescriptorLayoutTests: XCTestCase {
    /// Each recorded update and description picks its Darwin's layout, with no fallback.
    func testEachDarwinsRecordingsPickItsLayout() throws {
        let expected: [Int: [DescriptorLayout.Kind: DescriptorLayout]] = [22: [.tcp: .tcp22, .udp: .udp22],
                                                                          27: [.tcp: .tcp27, .udp: .udp23]]
        for darwin in [22, 27] {
            let messages = try descriptorMessages(darwin: darwin)
            XCTAssertGreaterThan(messages.count, 20)
            for (message, provider, offset) in messages {
                let layout = message.bytes.withUnsafeBytes {
                    DescriptorLayout.detect(provider.kind, $0, at: offset, fallback: { _ in nil })
                }
                XCTAssertEqual(layout, expected[darwin]?[provider.kind], "\(message.decoded)")
            }
        }
    }

    /// A layout 8 bytes short of the real one reads the last 8 bytes as an empty item and uses the message up as
    /// well: Darwin 22's TCP and UDP layouts on Darwin 23's messages. The domain item rules them out.
    func testTheDomainItemAnchorsTheLayout() {
        let build = NStatMessageBuilder(darwin: 23)
        let descriptor = NStatMessageBuilder.Descriptor(upid: 7, pid: 70, name: "curl")
        for (provider, short, real) in [(NStat.Provider.tcpUserland, DescriptorLayout.tcp22, DescriptorLayout.tcp23),
                                        (.udpSubflow, .udp22, .udp23)] {
            let update = build.update(5, provider, descriptor, items: [.domain("en.wikipedia.org")])
            update.withUnsafeBytes { bytes in
                let past = UnsafeRawBufferPointer(rebasing: bytes[(152 + short.size)...])
                XCTAssertTrue(FlowItems.forEachItem(in: past) { _, _ in }, "Without the anchor it would fit")
                XCTAssertFalse(short.fits(bytes, at: 152))
                XCTAssertEqual(DescriptorLayout.detect(provider.kind, bytes, at: 152, fallback: { _ in nil }), real)
            }
        }
        XCTAssertEqual(DescriptorLayout.known(.tcp).map(\.size), [360, 344, 336], "Largest first")
        XCTAssertEqual(DescriptorLayout.known(.udp).map(\.size), [280, 272])
    }

    /// A domain item that grew on a later macOS still anchors the layout: only its type and least length are
    /// required.
    func testAGrownDomainItemStillAnchors() {
        let build = NStatMessageBuilder()
        var domain = [UInt8](repeating: 0, count: 1_064)
        domain.replaceSubrange(0..<9, with: Array("a.example".utf8))
        let update = build.update(1, .tcpUserland, NStatMessageBuilder.Descriptor(pid: 9, name: "nscurl"),
                                  items: [.raw(1, domain)])
        update.withUnsafeBytes { bytes in
            XCTAssertEqual(DescriptorLayout.detect(.tcp, bytes, at: 152, fallback: { _ in nil }), .tcp27)
        }
    }

    /// A size no known layout has is read with the running framework's layout, if that fits too.
    func testAnUnknownSizeFallsBackToTheEncoding() {
        var build = NStatMessageBuilder()
        let grown = DescriptorLayout(kind: .tcp, size: 368, upid: 0, eupid: 8, start: 16, timestamp: 24, pid: 116,
                                     epid: 120, local: 124, remote: 152, pname: 196, ifnetProperties: 352, state: 76)
        build.tcp = grown
        let update = build.update(1, .tcpUserland, NStatMessageBuilder.Descriptor(pid: 9, name: "nscurl"))
        update.withUnsafeBytes { bytes in
            XCTAssertNil(DescriptorLayout.detect(.tcp, bytes, at: 152, fallback: { _ in nil }))
            XCTAssertNil(DescriptorLayout.detect(.tcp, bytes, at: 152, fallback: { _ in .tcp27 }), "It must fit too")
            XCTAssertEqual(DescriptorLayout.detect(.tcp, bytes, at: 152, fallback: { _ in grown }), grown)
        }
    }

    /// A descriptor whose name runs on, or whose address length doesn't go with its family, isn't taken.
    func testADescriptorMustLookLikeOne() {
        let build = NStatMessageBuilder()
        let good = build.update(1, .tcpKernel, NStatMessageBuilder.Descriptor(pid: 1, name: "tc"), items: [])
        var unnamed = good, misnamed = good, mislengthed = good
        unnamed.replaceSubrange((152 + 196)..<(152 + 260), with: [UInt8](repeating: 0x61, count: 64))
        misnamed[152 + 196] = 0x07
        mislengthed[152 + 152] = 28
        mislengthed[152 + 153] = UInt8(AF_INET)
        XCTAssertTrue(good.withUnsafeBytes { DescriptorLayout.tcp27.fits($0, at: 152) })
        for bad in [unnamed, misnamed, mislengthed] {
            XCTAssertFalse(bad.withUnsafeBytes { DescriptorLayout.tcp27.fits($0, at: 152) })
        }
    }
}
