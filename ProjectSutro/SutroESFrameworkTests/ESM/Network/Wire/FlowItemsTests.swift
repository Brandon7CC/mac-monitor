//
//  FlowItemsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Items
/// Pins what's read from an update's items: the host, URL and first-party site, which number holds each on every
/// Darwin, which host wins by provider, and that no blob, however broken, reads past its bytes.
final class FlowItemsTests: XCTestCase {
    /// Each recorded TCP userland update with parameters names Wikipedia, with an article's URL in TLV 153 on
    /// macOS 13.6 and TLV 42 on 27.2.
    func testRecordedParametersNameTheirRequest() throws {
        for darwin in [22, 27] {
            let read = try descriptorMessages(darwin: darwin).filter { $0.provider == .tcpUserland }.map { found in
                found.message.bytes.withUnsafeBytes { bytes in
                    let layout = DescriptorLayout.detect(.tcp, bytes, at: 152)!
                    return FlowItems.read(items: UnsafeRawBufferPointer(rebasing: bytes[(152 + layout.size)...]),
                                          provider: .tcpUserland)
                }
            }
            let urls = read.compactMap(\.url)
            XCTAssertFalse(urls.isEmpty, "Darwin \(darwin)")
            XCTAssertTrue(urls.allSatisfy { $0.hasPrefix("https://en.wikipedia.org/wiki/") }, "\(urls)")
            XCTAssertEqual(Set(read.compactMap(\.hostname)), ["en.wikipedia.org"])
        }
    }

    /// The host is TLV 3 for TCP and QUIC, since a tracker's domain item doesn't name the host. Anything else's is
    /// the domain item's, without its trailing dot. TLVs 42 and 153 are a URL on every Darwin, 34 the first-party site.
    func testItemsByProvider() {
        let parameters: [(UInt8, [UInt8])] = [(3, Array("en.wikipedia.org.\0".utf8)), (34, Array("wikipedia.org".utf8)),
                                              (153, Array("https://en.wikipedia.org/wiki/TCP?x=1#y\0".utf8))]
        let items: [NStatMessageBuilder.Item] = [.domain("tracker.example."), .parameters(parameters)]
        XCTAssertEqual(read(items, .tcpUserland), FlowItems(hostname: "en.wikipedia.org",
                                                           url: "https://en.wikipedia.org/wiki/TCP?x=1#y",
                                                           firstPartySite: "wikipedia.org"))
        XCTAssertEqual(read(items, .quicUserland).hostname, "en.wikipedia.org")
        XCTAssertEqual(read(items, .udpUserland).hostname, "tracker.example")
        XCTAssertEqual(read(items, .tcpKernel), FlowItems(hostname: "tracker.example"),
                       "No parameters for a kernel socket")
        XCTAssertEqual(read([.domain("www.apple.com.")], .udpSubflow).hostname, "www.apple.com")
        XCTAssertEqual(read([.domain("")], .tcpKernel), FlowItems())
        let other = [NStatMessageBuilder.Item.parameters([(42, Array("ftp://a.example/x".utf8)), (42, [0xFF, 0xFE]),
                                                          (153, Array("http://b.example/y".utf8))])]
        XCTAssertEqual(read(other, .tcpUserland).url, "http://b.example/y", "Only http and https, and only UTF-8")
    }

    /// The parameters walk stops at fewer than 5 bytes, as trailing padding is, and at a length past what remains.
    /// Items stop at a length past theirs.
    func testWalksStopAtTheirEnds() {
        let walked = { (blob: [UInt8]) -> [UInt8] in
            var seen: [UInt8] = []
            blob.withUnsafeBytes { FlowItems.forEachParameter(in: $0) { type, _ in seen.append(type) } }
            return seen
        }
        XCTAssertEqual(walked([3, 1, 0, 0, 0, 0x61, 0, 0, 0]), [3], "Padding")
        XCTAssertEqual(walked([3, 1, 0, 0, 0, 0x61, 3, 6, 0, 0, 0, 0x61]), [3], "The second runs past the end")
        XCTAssertEqual(walked([34, 0xFF, 0xFF, 0xFF, 0xFF, 0x61]), [], "A length of UInt32.max")
        let items = NStatMessageBuilder.bytes(of: .raw(9, [1, 2, 3])) + [5, 0, 0, 0, 200, 0, 0, 0]
        XCTAssertFalse(items.withUnsafeBytes { FlowItems.forEachItem(in: $0) { _, _ in } })
        XCTAssertTrue(NStatMessageBuilder.bytes(of: .raw(9, [1])).withUnsafeBytes {
            FlowItems.forEachItem(in: $0) { _, _ in }
        })
    }

    /// Broken and random blobs read without a crash: cut parameters, lengths past the end and of `UInt32.max`,
    /// values that aren't UTF-8, and 10,000 random blobs.
    func testBrokenItemsNeverReadPastTheirBytes() {
        var generator = SeededGenerator(seed: 28)
        let broken: [[UInt8]] = [[2, 0, 0, 0], [1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF], [2, 0, 0, 0, 6, 0, 0, 0, 3, 0xFF]]
        let random = (0..<10_000).map { _ in
            (0..<Int.random(in: 0...96, using: &generator)).map { _ in UInt8.random(in: 0...255, using: &generator) }
        }
        let parameters = random.prefix(1_000).map { NStatMessageBuilder.bytes(of: .parameters([(3, $0), (42, $0)])) }
        for blob in broken + random + parameters {
            for provider in [NStat.Provider.tcpUserland, .udpKernel] {
                _ = blob.withUnsafeBytes { FlowItems.read(items: $0, provider: provider) }
            }
            blob.withUnsafeBytes {
                FlowItems.forEachParameter(in: $0) { _, value in XCTAssertLessThanOrEqual(value.count, 96) }
            }
        }
    }

    /// The items a provider's update would carry, read.
    ///
    /// - Parameters:
    ///   - items: The items.
    ///   - provider: The provider.
    /// - Returns: What's read.
    private func read(_ items: [NStatMessageBuilder.Item], _ provider: NStat.Provider) -> FlowItems {
        items.flatMap(NStatMessageBuilder.bytes(of:)).withUnsafeBytes { FlowItems.read(items: $0, provider: provider) }
    }
}
