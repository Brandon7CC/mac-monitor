//
//  FlowURLTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - URLs
/// Pins what of a flow's URL is recorded: an `http` or `https` URL as the process gave it, nothing redacted, the part
/// after the host and port only when asked, and at most 2,048 bytes.
final class FlowURLTests: XCTestCase {
    /// Nothing is taken out: a user and password, a query, a fragment, and segments shaped like tokens all stay, as
    /// in the OCSP request trustd sent for syspolicyd, which has its request in its path.
    func testTheURLIsKeptAsGiven() {
        for url in ["HTTPS://user:pass@en.wikipedia.org:8443/wiki/Endpoint_security?token=abc#History",
                    "https://ocsp2.apple.com/ocsp03-devidg201/MFEwTzBNMEswSTAJBgUrDgMCGgUABBRL6lBBrmBeR1JqaH9oXGeBKC2/"
                        + "SlXUCJ/AhAPnLV0UOjMDkb8Kv9QQr1z",
                    "https://api.telegram.org/bot123456:AAH-xY_z/sendMessage",
                    "https://hooks.slack.com/services/T0001/B0002/abcdef",
                    "https://discord.com/api/v10/webhooks/1234/tok-en",
                    "https://a.example/auth/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln/done",
                    "https://a.example/blob/0123456789abcdef0123456789ABCDEF",
                    "http://[::ffff:198.35.26.224]:80/x#a@b",
                    "https://example.com?a=1",
                    "https://example.com/"] {
            XCTAssertEqual(FlowURL.recorded(url, keepingPath: true), url)
        }
    }

    /// With Record URL paths off, a URL ends at its host and port, and keeps whatever came before them.
    func testWithoutItsPathAURLEndsAtTheHostAndPort() {
        XCTAssertEqual(FlowURL.recorded("https://user:pass@en.wikipedia.org:8443/wiki/x?a=1", keepingPath: false),
                       "https://user:pass@en.wikipedia.org:8443")
        XCTAssertEqual(FlowURL.recorded("https://example.com?a=1#b", keepingPath: false), "https://example.com")
    }

    /// Only an `http` or `https` URL that names a host is a URL to record.
    func testOtherSchemesAndNoHostAreRefused() {
        for refused in ["ftp://example.com/x", "file:///etc/passwd", "example.com/x", "https://", "https://user@/x"] {
            XCTAssertNil(FlowURL.recorded(refused, keepingPath: true), refused)
        }
    }

    /// A URL is cut to 2,048 UTF-8 bytes, at a character's end.
    func testALongURLIsCut() throws {
        let url = try XCTUnwrap(FlowURL.recorded("https://a.example/x" + String(repeating: "é", count: 1_100),
                                                 keepingPath: true))
        XCTAssertEqual(url.utf8.count, 2_047)
        XCTAssertTrue(url.hasSuffix("é"))
    }
}
