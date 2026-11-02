//
//  AuditTokenStringTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Audit token strings
/// Pins `AuditToken.toString()` (each process's `audit_token_string` and friends) to the interpolated string it was:
/// every field labeled, in order, in decimal.
final class AuditTokenStringTests: XCTestCase {
    /// The string as it was interpolated before.
    ///
    /// - Parameter token: The token.
    /// - Returns: Its fields, labeled.
    private func interpolated(_ token: AuditToken) -> String {
        "pid:\(token.pid), euid:\(token.euid), ruid:\(token.ruid), rgid:\(token.rgid), egid:\(token.egid), "
            + "asid:\(token.asid), auid:\(token.auid), pidversion:\(token.pidversion)"
    }
    
    /// A token with the given fields.
    ///
    /// - Parameters:
    ///   - small: The 32-bit fields: pid, pidversion and asid.
    ///   - large: The 64-bit fields: auid, euid, ruid, rgid and egid.
    /// - Returns: The token.
    private func token(_ small: Int32, _ large: Int64) -> AuditToken {
        var token = AuditToken(from: audit_token_t())
        (token.pid, token.pidversion, token.asid) = (small, small &+ 1, small &- 1)
        (token.auid, token.euid, token.ruid, token.rgid, token.egid) = (large, large &+ 1, large &- 1, 0, 0 &- large)
        return token
    }
    
    /// Zeros, ends of every width, and random values.
    func testMatchesInterpolation() {
        var tokens = [AuditToken(from: audit_token_t()), token(1, 501), token(.max, .max), token(.min, .min),
                      token(-1, 4_294_967_295), token(100_000, -2)]
        for _ in 0..<2_000 {
            tokens.append(token(.random(in: .min ... .max), .random(in: .min ... .max)))
        }
        for token in tokens {
            XCTAssertEqual(token.toString(), interpolated(token))
        }
    }
}
