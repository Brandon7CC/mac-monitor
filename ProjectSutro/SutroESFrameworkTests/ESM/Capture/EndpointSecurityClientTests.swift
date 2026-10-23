//
//  EndpointSecurityClientTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Endpoint Security clients
/// Pins what the live client layer can show without root: how `es_new_client`'s results are reported, and the audit
/// token a capture session mutes itself with.
final class EndpointSecurityClientTests: XCTestCase {
    /// Every result `es_new_client` can return is reported as its own `NewClientResult`.
    func testESResultsMapToNewClientResult() {
        let expected: [(es_new_client_result_t, NewClientResult)] = [
            (ES_NEW_CLIENT_RESULT_SUCCESS, .success),
            (ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT, .invalidArgument),
            (ES_NEW_CLIENT_RESULT_ERR_INTERNAL, .internalSubsystem),
            (ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED, .notEntitled),
            (ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED, .notPermitted),
            (ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED, .notPrivileged),
            (ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS, .tooManyClients)
        ]
        for (result, reported) in expected {
            XCTAssertEqual(NewClientResult(result), reported, "\(result.rawValue)")
        }
        XCTAssertEqual(NewClientResult(es_new_client_result_t(rawValue: 1_000)), .internalSubsystem)
    }
    
    /// The audit token a capture session mutes is this process's.
    func testCurrentProcessAuditToken() {
        let token = audit_token_t.currentProcess
        XCTAssertEqual(token.pid(), getpid())
        XCTAssertEqual(token.euid(), Int64(geteuid()))
        XCTAssertGreaterThan(token.pidversion(), 0)
    }
}
