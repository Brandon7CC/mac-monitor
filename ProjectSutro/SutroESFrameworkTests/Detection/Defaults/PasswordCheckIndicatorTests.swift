//
//  PasswordCheckIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Password checked with dscl
/// Pins Password checked with dscl on the events `macmonitor stream` recorded on macOS 27
/// (`Fixtures/macmonitor-3.1-dscl.jsonl`): a shell running `/usr/bin/dscl /Local/Default -authonly`, `dscl . -authonly`
/// through `PATH`, and `dscl /Search -read`. The Security Extension's compiled set and Mac Monitor's own matching find
/// it on the two checks only, the extension's hit is stamped as a shipped medium indicator, and the rule is evaluated
/// only on execs of a binary named dscl. The records' empty verdicts are the recording build's, which didn't ship it.
final class PasswordCheckIndicatorTests: XCTestCase {
    /// The fixture's events, in the order they ran.
    private static let fixture = "macmonitor-3.1-dscl.jsonl"

    /// Each recorded exec is a check exactly when it's dscl's with `-authonly`, in the extension and in the app alike:
    /// not the shell whose arguments hold both checks, nor dscl reading a record.
    func testRecordedChecksMatch() throws {
        let id = try shippedID("Password checked with dscl")
        let messages = try fixtureMessages(Self.fixture)
        XCTAssertEqual(messages.map(\.es_event_type), Array(repeating: "ES_EVENT_TYPE_NOTIFY_EXEC", count: 4))
        var values = MessageValueCache()
        var matched: [Bool] = []
        for message in messages {
            let evaluation = Self.shippedIndicators.evaluate(message, values: &values)
            XCTAssertEqual(evaluation.undetermined, [], message.context ?? "")
            XCTAssertEqual(evaluation.hits.map(\.id), try matcherHits(message), message.context ?? "")
            matched.append(evaluation.hits.contains { $0.id == id })
        }
        XCTAssertEqual(matched, [false, true, true, false], messages.map { $0.context ?? "" }.description)
    }

    /// A recorded check is stamped as the Security Extension stamps it: the indicator's name, medium, Credential
    /// Access's T1056.002, shipped and unedited, and the verdict survives the wire.
    func testCheckIsStampedAsShippedMedium() throws {
        let id = try shippedID("Password checked with dscl")
        var message = try XCTUnwrap(try fixtureMessages(Self.fixture).dropFirst().first)
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let hit = try XCTUnwrap(message.indicators?.hits.first { $0.id == id })
        XCTAssertEqual(hit.name, "Password checked with dscl")
        XCTAssertEqual(hit.severity, .medium)
        XCTAssertEqual(hit.tactic_id, "TA0006")
        XCTAssertEqual(hit.technique, "T1056.002")
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(hit.edited)
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators)
    }

    /// The rule runs on execs only, and the index evaluates it only on an exec whose target is named exactly dscl, so
    /// every other exec costs it one lookup and no scan of its command line.
    func testRuleIsAnchoredOnDsclsName() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "Password checked with dscl" })
        let rule = try IndicatorCompiler.compile(indicator.predicate).get()
        let exec = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
        XCTAssertEqual(rule.types, [exec])
        guard case .anyOf(let anchors) = rule.program.necessity(eventType: exec) else {
            return XCTFail("Not anchored")
        }
        let described = anchors.map { anchor in
            let bytes = rule.program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
            return "\(anchor.field) \(anchor.shape) \(String(decoding: bytes, as: UTF8.self))"
        }
        XCTAssertEqual(described, ["execTargetExecutableName exact dscl"])
    }
}
