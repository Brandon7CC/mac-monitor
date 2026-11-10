//
//  AdhocSigningIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Adhoc signing as Endpoint Security reports it
/// Pins Adhoc signed, Unsigned and Unsigned code resolved a name on the signing Mac Monitor 3.0's stream recorded on a
/// Mac with SIP on, macOS 27.2 (`Fixtures/macmonitor-3.0-signing.jsonl`): zsh execing a linker-signed adhoc program and
/// one re-signed with `codesign -s -`, a Developer ID program and Apple's `/usr/bin/true`, then each adhoc program,
/// running, execing `/bin/sh`. Endpoint Security reports `CS_ADHOC` and `ADHOC` for the adhoc code, as an exec's
/// target and as a running process alike, with no team ID and not a platform binary.
///
/// With the code signing checks off, as on the SIP-off test VM, every process is a platform binary with no team ID,
/// so both rules trust only the adhoc flag and type: the VM's adhoc program (`Fixtures/macmonitor-3.1-resolver.jsonl`)
/// still matches, and a Developer ID program reported that way doesn't. The Security Extension's compiled set and Mac
/// Monitor's own matching agree on every case.
final class AdhocSigningIndicatorTests: XCTestCase {
    /// The fixture's execs, in the order they ran.
    private static let fixture = "macmonitor-3.0-signing.jsonl"
    /// The resolver fixture, recorded on the SIP-off test VM. Its last event is an adhoc program's connect to the
    /// resolver's socket.
    private static let resolverFixture = "macmonitor-3.1-resolver.jsonl"
    /// `CS_ADHOC`.
    private static let adhocFlag: Int64 = 0x0000_0002
    /// `CS_PLATFORM_BINARY`, which macOS sets on every process with its code signing checks off.
    private static let platformFlag: Int64 = 0x0400_0000

    /// Each exec's target, and each adhoc program as the process of its own exec, is signed as recorded: adhoc code
    /// has `CS_ADHOC`, is `ADHOC`, with no team ID and not a platform binary.
    func testRecordedSigningWithSIPOn() throws {
        let messages = try fixtureMessages(Self.fixture)
        XCTAssertEqual(messages.map(\.sip_status), Array(repeating: "enabled", count: 6))
        let targets = try messages.map(target)
        XCTAssertEqual(targets.map(\.codesigning_type), [.adhoc, .adhoc, .developerId, .platform, .platform, .platform])
        XCTAssertEqual(targets.map(\.is_adhoc_signed), [true, true, false, false, false, false])
        XCTAssertEqual(targets.map(\.is_platform_binary), [false, false, false, true, true, true])
        XCTAssertEqual(targets.map(\.team_id), [nil, nil, "4HMJQ7V3SX", nil, nil, nil])
        XCTAssertEqual(targets.map { $0.codesigning_flags & Self.adhocFlag != 0 },
                       [true, true, false, false, false, false])
        for running in messages[4...].map(\.process) {
            XCTAssertEqual(running.codesigning_type, .adhoc, running.executable?.path ?? "")
            XCTAssertTrue(running.is_adhoc_signed)
            XCTAssertNotEqual(running.codesigning_flags & Self.adhocFlag, 0)
            XCTAssertFalse(running.is_platform_binary)
            XCTAssertNil(running.team_id)
        }
    }

    /// Adhoc signed matches the execs of both adhoc programs, and not the Developer ID program's, Apple's
    /// `/usr/bin/true`'s, or the adhoc programs' execs of `/bin/sh`: it reads the code run, not the process running.
    /// Unsigned matches none of them: every program recorded is signed.
    func testAdhocSignedMatchesTheRecordedExecs() throws {
        let id = try shippedID("Adhoc signed"), unsigned = try shippedID("Unsigned")
        XCTAssertEqual([id, unsigned], [Indicator.uuid(10), Indicator.uuid(61)])
        let messages = try fixtureMessages(Self.fixture)
        for (message, matches) in zip(messages, [true, true, false, false, false, false]) {
            try assertShippedMatch(message, matches, id: id, message.context ?? "")
            try assertShippedMatch(message, false, id: unsigned, message.context ?? "")
        }
    }

    /// Unsigned matches an exec of code with no signing ID, with one that says nothing, or typed `UNSIGNED` though it
    /// has one, as code whose signature is no longer valid is. Adhoc signed doesn't match those, and Unsigned doesn't
    /// match adhoc code, even without a signing ID: no exec matches both, so each colors its own label.
    func testUnsignedMatchesCodeWithoutASignature() throws {
        let adhoc = try shippedID("Adhoc signed"), unsigned = try shippedID("Unsigned")
        let messages = try fixtureMessages(Self.fixture)
        let developerID = try target(messages[2])
        let unsignedTargets: [(String, (inout SutroESFramework.Process) -> Void)] = [
            ("no signing ID", { $0.signing_id = nil }),
            ("an empty signing ID", { $0.signing_id = "" }),
            ("an unknown signing ID", { $0.signing_id = "Unknown" }),
            ("a signature no longer valid", { $0.codesigning_type = .unsigned }),
        ]
        for (label, change) in unsignedTargets {
            var process = developerID
            change(&process)
            let message = try exec(messages[2], target: process)
            try assertShippedMatch(message, true, id: unsigned, label)
            try assertShippedMatch(message, false, id: adhoc, label)
        }
        var bare = try target(messages[0])
        bare.signing_id = nil
        let message = try exec(messages[0], target: bare)
        try assertShippedMatch(message, true, id: adhoc, "adhoc, no signing ID")
        try assertShippedMatch(message, false, id: unsigned, "adhoc, no signing ID")
    }

    /// Both color an exec's label by default, orange and red, and what they match together is what Adhoc or unsigned,
    /// 3.0's, matched.
    func testTheSplitKeepsAdhocOrUnsigned() throws {
        let adhoc = try XCTUnwrap(Indicator.defaults.first { $0.name == "Adhoc signed" })
        let unsigned = try XCTUnwrap(Indicator.defaults.first { $0.name == "Unsigned" })
        XCTAssertEqual([adhoc.tableMarks, unsigned.tableMarks], [[.dot, .symbol, .label], [.dot, .symbol, .label]])
        XCTAssertEqual([adhoc.color, unsigned.color], [.orange, .red])
        XCTAssertEqual([adhoc.symbol, unsigned.symbol], ["xmark.seal", "xmark.seal"])
        let both = ownIndicator("Adhoc or unsigned", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "#
            + #"(event.exec.target.codesigning_type IN {"ADHOC", "UNSIGNED"} OR event.exec.target.is_adhoc_signed "#
            + #"== YES OR event.exec.target.signing_id == nil OR event.exec.target.signing_id IN {"", "Unknown"})"#)
        let compiled = CompiledIndicators([both, adhoc, unsigned])
        XCTAssertEqual(compiled.count, 3)
        let messages = try fixtureMessages(Self.fixture)
        var targets = try messages.map(target)
        for change in [{ (process: inout SutroESFramework.Process) in process.signing_id = nil },
                       { $0.codesigning_type = .unsigned }, { $0.is_adhoc_signed = true }] {
            targets += try messages.map { message in
                var process = try target(message)
                change(&process)
                return process
            }
        }
        var values = MessageValueCache()
        for process in targets {
            let hits = Set(compiled.hits(for: try exec(messages[0], target: process), values: &values).map(\.id))
            let matched = [adhoc.id, unsigned.id].filter(hits.contains)
            XCTAssertEqual(!matched.isEmpty, hits.contains(both.id), process.signing_id ?? "nil")
            XCTAssertLessThan(matched.count, 2, process.signing_id ?? "nil")
        }
    }

    /// With the checks off, an adhoc program execed is still Adhoc signed, by its flag, though it's a platform
    /// binary. A Developer ID program reported as one, with no team ID, isn't.
    func testAdhocSignedWithChecksOff() throws {
        let id = try shippedID("Adhoc signed")
        let messages = try fixtureMessages(Self.fixture)
        let vmAdhoc = try recordedResolverConnect().process
        XCTAssertTrue(vmAdhoc.is_platform_binary && vmAdhoc.is_adhoc_signed && vmAdhoc.team_id == nil)
        try assertShippedMatch(try exec(messages[0], target: vmAdhoc), true, id: id, "adhoc, checks off")
        try assertShippedMatch(try exec(messages[2], target: checksOff(try target(messages[2]))), false, id: id,
                               "Developer ID, checks off")
    }

    /// Unsigned code resolved a name matches the resolver connect, recorded on the VM, made by each adhoc program as
    /// recorded with SIP on, running or as an exec's target. Not by the Developer ID program, Apple's
    /// `/usr/bin/true`, or zsh.
    func testResolverConnectByTheRecordedProcesses() throws {
        let id = try shippedID("Unsigned code resolved a name")
        let messages = try fixtureMessages(Self.fixture)
        let connect = try recordedResolverConnect()
        let signers: [(SutroESFramework.Process, Bool, String)] = [
            (messages[4].process, true, "running linker-signed adhoc"),
            (messages[5].process, true, "running re-signed adhoc"),
            (try target(messages[0]), true, "linker-signed adhoc"),
            (try target(messages[1]), true, "re-signed adhoc"),
            (try target(messages[2]), false, "Developer ID"),
            (try target(messages[3]), false, "/usr/bin/true"),
            (messages[0].process, false, "zsh"),
        ]
        for (signer, matches, label) in signers {
            var message = connect
            message.process = signer
            try assertShippedMatch(message, matches, id: id, label)
        }
    }

    /// With the checks off, the adhoc program's recorded connect matches, by its flag. A Developer ID program reported
    /// as a platform binary with no team ID doesn't, nor does code signed with a certificate that has no team ID,
    /// which isn't adhoc.
    func testResolverConnectWithChecksOff() throws {
        let id = try shippedID("Unsigned code resolved a name")
        let connect = try recordedResolverConnect()
        try assertShippedMatch(connect, true, id: id, "adhoc, checks off")
        let developerID = try target(try fixtureMessages(Self.fixture)[2])
        var vmDeveloperID = connect
        vmDeveloperID.process = checksOff(developerID)
        try assertShippedMatch(vmDeveloperID, false, id: id, "Developer ID, checks off")
        var selfSigned = connect
        selfSigned.process = developerID
        selfSigned.process.team_id = nil
        selfSigned.process.codesigning_type = .unknown
        selfSigned.process.enrich()
        try assertShippedMatch(selfSigned, false, id: id, "no team ID, not adhoc")
    }
}


// MARK: - Deriving events
extension AdhocSigningIndicatorTests {
    /// - Parameter message: An exec.
    /// - Returns: Its event.
    /// - Throws: A failure when it isn't an exec.
    private func execEvent(_ message: Message) throws -> ProcessExecEvent {
        guard case .exec(let exec) = message.event else {
            return try XCTUnwrap(nil as ProcessExecEvent?, "Not an exec")
        }
        return exec
    }

    /// - Parameter message: An exec.
    /// - Returns: Its target.
    /// - Throws: A failure when it isn't an exec.
    private func target(_ message: Message) throws -> SutroESFramework.Process {
        try execEvent(message).target
    }

    /// - Parameters:
    ///   - message: An exec.
    ///   - target: Its new target.
    /// - Returns: The exec with its target changed.
    /// - Throws: A failure when it isn't an exec.
    private func exec(_ message: Message, target: SutroESFramework.Process) throws -> Message {
        var exec = try execEvent(message)
        var message = message
        exec.target = target
        message.event = .exec(exec)
        return message
    }

    /// - Returns: The resolver fixture's adhoc connect to the resolver's socket, recorded on the SIP-off test VM.
    /// - Throws: The error reading the fixture.
    private func recordedResolverConnect() throws -> Message {
        try XCTUnwrap(try fixtureMessages(Self.resolverFixture).last)
    }

    /// A process as macOS reports it with its code signing checks off: a platform binary with no team ID, its
    /// `CS_ADHOC` flag as it was, and its type derived again.
    ///
    /// - Parameter process: The process as reported with the checks on.
    /// - Returns: The process.
    private func checksOff(_ process: SutroESFramework.Process) -> SutroESFramework.Process {
        var process = process
        process.codesigning_flags |= Self.platformFlag
        process.is_platform_binary = true
        process.team_id = nil
        process.enrich()
        return process
    }
}
