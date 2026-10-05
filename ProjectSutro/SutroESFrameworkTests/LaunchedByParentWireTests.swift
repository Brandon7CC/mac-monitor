//
//  LaunchedByParentWireTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The launched-by parent over XPC
/// Pins that a Security Extension and an app of different versions still read each other's events: the launched-by
/// parent is one added key, an event without one gets one from the app, and one that can't be read never costs the
/// event.
final class LaunchedByParentWireTests: XCTestCase {
    /// Mac Monitor 2.1's fork event, as its app decoded it: no launched-by parent.
    private struct ForkBefore22: Decodable {
        let id: UUID
        let child: SutroESFramework.Process
    }
    
    /// A `Message` holding a fork, as Mac Monitor 2.1's app decoded it.
    private struct MessageBefore22: Decodable {
        let event_type: Int
        let event: [String: [String: ForkBefore22]]
    }
    
    /// The answer for the shell's child.
    ///
    /// - Parameter resolvedBy: Who resolved it.
    /// - Returns: The shell, named from the forking process's executable.
    private func shellAnswer(by resolvedBy: LaunchedByParent.ResolvedBy) -> LaunchedByParent {
        LaunchedByParent(source: .unixParent, audit_token: .fixture(pid: 401, pidversion: 4010), path: "/usr/bin/true",
                         resolved_by: resolvedBy)
    }
    
    /// What a Security Extension sends for a shell's fork of pid 402: its JSON object.
    ///
    /// - Returns: The object.
    /// - Throws: An `XCTest` failure if it wasn't serialized, or the error parsing it.
    private func sentFork() throws -> [String: Any] {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        fixture.fork(childPID: 402, parent: RawMessageFixture.auditToken(pid: 401, pidversion: 4010),
                     responsible: RawMessageFixture.auditToken(pid: 300, pidversion: 3000))
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        let json = try XCTUnwrap(MessageSerializer(processPath: { _, _ in nil }).serialize(fixture.raw, in: lane))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
    }
    
    /// The object with the fork's launched-by parent replaced.
    ///
    /// - Parameters:
    ///   - object: A fork's JSON object.
    ///   - value: The new value of `event.fork._0.launched_by_parent`, or `nil` to remove the key.
    /// - Returns: The object.
    /// - Throws: An `XCTest` failure if it isn't a fork.
    private func replacingLaunchedByParent(in object: [String: Any], with value: Any?) throws -> [String: Any] {
        var object = object
        var event = try XCTUnwrap(object["event"] as? [String: Any])
        var fork = try XCTUnwrap(event["fork"] as? [String: Any])
        var payload = try XCTUnwrap(fork["_0"] as? [String: Any])
        payload["launched_by_parent"] = value
        fork["_0"] = payload
        event["fork"] = fork
        object["event"] = event
        return object
    }
    
    /// Decode an object as the app decodes the events it receives.
    ///
    /// - Parameter object: The event's JSON object.
    /// - Returns: The event.
    /// - Throws: The decoder's error.
    private func received(_ object: [String: Any]) throws -> Message {
        try JSONDecoder().decode(Message.self, from: JSONSerialization.data(withJSONObject: object))
    }
    
    /// From a 2.2 Security Extension to a 2.2 app: the launched-by parent arrives as stamped, on a fork and on an exec.
    ///
    /// - Throws: An `XCTest` failure, or an encoder's or decoder's error.
    func testFromThisVersion() throws {
        let fork = try received(try sentFork())
        XCTAssertEqual(fork.createdLaunchedByParent, shellAnswer(by: .securityExtension))
        let record = try esloggerExec(parent: (1, 1), env: ["XPC_SERVICE_NAME=com.example.agent"])
        var exec = try importRecord(try execedByXPCProxy(record))
        exec.resolveLaunchedByParent(by: .securityExtension) { _, _ in nil }
        let execReceived = try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(exec))
        XCTAssertEqual(execReceived.createdLaunchedByParent, exec.createdLaunchedByParent)
        XCTAssertEqual(execReceived.createdLaunchedByParent?.launchd_job?.label, "com.example.agent")
    }
    
    /// From an older Security Extension: no launched-by parent, which the app then resolves itself.
    ///
    /// - Throws: An `XCTest` failure, or the decoder's error.
    func testFromAnOlderSecurityExtension() throws {
        var fork = try received(try replacingLaunchedByParent(in: try sentFork(), with: nil))
        XCTAssertNil(fork.createdLaunchedByParent)
        fork.resolveLaunchedByParent(by: .app) { _, _ in
            XCTFail("A fork's parent is named by the message")
            return nil
        }
        XCTAssertEqual(fork.createdLaunchedByParent, shellAnswer(by: .app))
    }
    
    /// To an older app: the only change is the added `event.fork._0.launched_by_parent`, which its decoder ignores.
    ///
    /// - Throws: An `XCTest` failure, or an encoder's or decoder's error.
    func testToAnOlderApp() throws {
        let stamped = try received(try sentFork())
        var unstamped = stamped
        unstamped.setLaunchedByParent(nil)
        let object = { (message: Message) in try JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) }
        let new = try XCTUnwrap(try object(stamped) as? [String: Any])
        let old = try XCTUnwrap(try object(unstamped) as? [String: Any])
        XCTAssertEqual(addedKeyPaths(new, old), ["event.fork._0.launched_by_parent"])
        XCTAssertEqual(differences(old, new), [])
        
        let decoded = try JSONDecoder().decode(MessageBefore22.self, from: JSONSerialization.data(withJSONObject: new))
        XCTAssertEqual(decoded.event["fork"]?["_0"]?.child.pid, 402)
        XCTAssertEqual(decoded.event_type, Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue))
    }
    
    /// A launched-by parent from a newer writer, with a source or resolver this version doesn't know, reads as none,
    /// and the event still reads, from the Security Extension and from a trace.
    ///
    /// - Throws: An `XCTest` failure, or a decoder's error.
    func testUnknownValuesReadAsNone() throws {
        let sent = try sentFork()
        let fork = try XCTUnwrap(try event("fork", in: sent)["_0"] as? [String: Any])
        let launchedByParent = try XCTUnwrap(fork["launched_by_parent"] as? [String: Any])
        for (key, value) in [("source", "elsewhere"), ("resolved_by", "someone")] {
            var newer = launchedByParent
            newer[key] = value
            let object = try replacingLaunchedByParent(in: sent, with: newer)
            XCTAssertNil(try received(object).createdLaunchedByParent, key)
            XCTAssertNil(try importRecord(object).createdLaunchedByParent, key)
        }
    }
    
    /// A launched-by parent of the wrong JSON type reads as none rather than costing the event.
    ///
    /// - Throws: An `XCTest` failure, or a decoder's error.
    func testWrongTypeReadsAsNone() throws {
        let sent = try sentFork()
        for value: Any in ["unix_parent", 42, [Any](), NSNull()] {
            let object = try replacingLaunchedByParent(in: sent, with: value)
            XCTAssertNil(try received(object).createdLaunchedByParent, "\(value)")
            XCTAssertNil(try importRecord(object).createdLaunchedByParent, "\(value)")
        }
    }
    
    /// The key paths of `new` that `old` lacks, outermost only.
    ///
    /// - Parameters:
    ///   - new: A JSON value.
    ///   - old: The JSON value it's compared with.
    ///   - path: The key path of `new`.
    /// - Returns: The added key paths, sorted.
    private func addedKeyPaths(_ new: Any, _ old: Any?, path: String = "") -> [String] {
        guard let new = new as? [String: Any], let old = old as? [String: Any] else { return [] }
        return new.keys.sorted().flatMap { key -> [String] in
            let child = path.isEmpty ? key : "\(path).\(key)"
            guard let value = old[key] else { return [child] }
            return addedKeyPaths(new[key]!, value, path: child)
        }
    }
}
