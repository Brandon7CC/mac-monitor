//
//  FlowURLTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - URLs
/// Pins what of a flow's URL is recorded: `http` and `https` only, never a user and password, a query or a
/// fragment, the path only when asked, and each secret-shaped segment redacted.
final class FlowURLTests: XCTestCase {
    /// The scheme and authority stay, without credentials. A query and a fragment never do. Without its path, a URL
    /// ends at the host and port.
    func testWhatIsKept() {
        let url = "HTTPS://user:pass@en.wikipedia.org:8443/wiki/Endpoint_security?token=abc#History"
        XCTAssertEqual(FlowURL.sanitized(url, keepingPath: true),
                       "https://en.wikipedia.org:8443/wiki/Endpoint_security")
        XCTAssertEqual(FlowURL.sanitized(url, keepingPath: false), "https://en.wikipedia.org:8443")
        XCTAssertEqual(FlowURL.sanitized("http://[::ffff:198.35.26.224]:80/x#a@b", keepingPath: true),
                       "http://[::ffff:198.35.26.224]:80/x")
        XCTAssertEqual(FlowURL.sanitized("https://example.com?a=1", keepingPath: true), "https://example.com")
        XCTAssertEqual(FlowURL.sanitized("https://example.com/", keepingPath: true), "https://example.com/")
        for refused in ["ftp://example.com/x", "file:///etc/passwd", "example.com/x", "https://", "https://user@/x"] {
            XCTAssertNil(FlowURL.sanitized(refused, keepingPath: true), refused)
        }
    }

    /// Each secret's shape is redacted where it stands, so the path keeps its structure.
    func testSecretsAreRedacted() {
        let cases = [
            ("https://api.telegram.org/bot123456:AAH-xY_z/sendMessage",
             "https://api.telegram.org/bot123456:<redacted>/sendMessage"),
            ("https://hooks.slack.com/services/T0001/B0002/abcdef",
             "https://hooks.slack.com/services/T0001/B0002/<redacted>"),
            ("https://discord.com/api/webhooks/1234/tok-en", "https://discord.com/api/webhooks/1234/<redacted>"),
            ("https://discord.com/api/v10/webhooks/1234/tok-en",
             "https://discord.com/api/v10/webhooks/1234/<redacted>"),
            ("https://a.example/auth/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln/done",
             "https://a.example/auth/<redacted>/done"),
            ("https://a.example/blob/0123456789abcdef0123456789ABCDEF", "https://a.example/blob/<redacted>"),
            ("https://a.example/k/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg", "https://a.example/k/<redacted>")
        ]
        for (raw, recorded) in cases {
            XCTAssertEqual(FlowURL.sanitized(raw, keepingPath: true), recorded, raw)
        }
    }

    /// What isn't shaped like a secret stays: slugs, short hex, a 32-character segment without a digit, and names
    /// that only start like a bot or a token.
    func testOrdinaryPathsStay() {
        for path in ["/how-to-configure-network-extension-filters-on-macos-13", "/commit/0123abcd", "/bot/start",
                     "/botany:x", "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "/eyJ-not-a-token", "/api/v10/users/1234/x",
                     "/services/T0001/B0002"] {
            XCTAssertEqual(FlowURL.sanitized("https://a.example" + path, keepingPath: true), "https://a.example" + path)
        }
    }

    /// A URL is cut to 2,048 UTF-8 bytes, at a character's end.
    func testALongURLIsCut() throws {
        let url = try XCTUnwrap(FlowURL.sanitized("https://a.example/x" + String(repeating: "é", count: 1_100),
                                                  keepingPath: true))
        XCTAssertEqual(url.utf8.count, 2_047)
        XCTAssertTrue(url.hasSuffix("é"))
    }
}
