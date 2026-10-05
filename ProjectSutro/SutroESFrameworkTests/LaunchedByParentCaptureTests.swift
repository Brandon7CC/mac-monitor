//
//  LaunchedByParentCaptureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Stamping the launched-by parent
/// Pins how the Security Extension stamps a created process's launched-by parent as it serializes an exec or fork, and
/// only then: from the message's own fields, without changing how the event streams.
final class LaunchedByParentCaptureTests: XCTestCase {
    /// A shell, and the terminal app it runs in.
    private let shell = RawMessageFixture.auditToken(pid: 401, pidversion: 4010)
    private let terminal = RawMessageFixture.auditToken(pid: 300, pidversion: 3000)
    
    /// The answer for the shell's child: the shell, named from the forking process's executable.
    private var shellAnswer: LaunchedByParent {
        LaunchedByParent(source: .unixParent, audit_token: .fixture(pid: 401, pidversion: 4010), path: "/usr/bin/true",
                         resolved_by: .securityExtension)
    }
    
    /// A `path` that fails the test if it's called.
    ///
    /// - Parameter line: The caller's line, for the failure.
    /// - Returns: The closure.
    private func noPaths(line: UInt = #line) -> (Int32, AuditToken?) -> String? {
        { pid, _ in
            XCTFail("Read the path of \(pid)", line: line)
            return nil
        }
    }
    
    /// The shell's fork of pid 402, which stays alive until the test ends.
    ///
    /// - Returns: The message's fixture.
    private func shellFork() -> RawMessageFixture {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        fixture.fork(childPID: 402, parent: shell, responsible: terminal)
        return fixture
    }
    
    /// Serialize a message as a process lane does.
    ///
    /// - Parameters:
    ///   - fixture: The message.
    ///   - serializer: The serializer.
    /// - Returns: The event's JSON object.
    /// - Throws: An `XCTest` failure if it wasn't serialized, or the error parsing it.
    private func serialize(_ fixture: RawMessageFixture, with serializer: MessageSerializer) throws -> [String: Any] {
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        let json = try XCTUnwrap(serializer.serialize(fixture.raw, in: lane))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
    }
    
    /// A fork's child is stamped with its Unix parent, the forking process, named by its executable: no path is read.
    ///
    /// - Throws: An `XCTest` failure if the event has no launched-by parent, or the error parsing it.
    func testSerializerStampsFork() throws {
        let object = try serialize(shellFork(), with: MessageSerializer(processPath: noPaths()))
        let fork = try XCTUnwrap(try event("fork", in: object)["_0"] as? [String: Any])
        let launchedByParent = try XCTUnwrap(fork["launched_by_parent"] as? [String: Any])
        XCTAssertEqual(launchedByParent["source"] as? String, "unix_parent")
        XCTAssertEqual(launchedByParent["pid"] as? Int, 401)
        XCTAssertEqual(launchedByParent["path"] as? String, "/usr/bin/true")
        XCTAssertEqual(launchedByParent["resolved_by"] as? String, "security_extension")
        XCTAssertTrue(launchedByParent["launchd_job"] is NSNull)
        let token = try XCTUnwrap(launchedByParent["audit_token"] as? [String: Any])
        XCTAssertEqual(token["pidversion"] as? Int, 4010)
        XCTAssertNil(token["id"])
    }
    
    /// A lane names a launched-by parent from the processes its execs and forks named before, and reads the path of one
    /// it hasn't seen only once.
    ///
    /// - Throws: An `XCTest` failure if an event wasn't serialized or has no launched-by parent.
    func testLaneRemembersProcessPaths() throws {
        var reads: [Int32] = []
        let serializer = MessageSerializer(processPath: { pid, _ in
            reads.append(pid)
            return "/read/\(pid)"
        })
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        /// The responsible process's path stamped on a launchd fork of `child`.
        func responsiblePath(child: Int32, responsible: audit_token_t) throws -> String? {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
            fixture.fork(childPID: child, parent: RawMessageFixture.auditToken(pid: 1, pidversion: 1),
                         responsible: responsible)
            let json = try XCTUnwrap(serializer.serialize(fixture.raw, in: lane))
            let message = try JSONDecoder().decode(Message.self, from: json)
            let launchedByParent = try XCTUnwrap(message.createdLaunchedByParent)
            XCTAssertEqual(launchedByParent.source, .responsibleProcess)
            return launchedByParent.path
        }
        
        /// An app forks: the lane remembers it, and names it as an XPC service's responsible process.
        let app = RawMessageFixture.auditToken(pid: 500, pidversion: 5000)
        let appFork = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        appFork.fork(childPID: 501, parent: app, responsible: app)
        XCTAssertNotNil(serializer.serialize(appFork.raw, in: lane))
        XCTAssertEqual(try responsiblePath(child: 420, responsible: app), "/usr/bin/true")
        /// A responsible process the lane hasn't seen is read once.
        let other = RawMessageFixture.auditToken(pid: 600, pidversion: 6000)
        XCTAssertEqual(try responsiblePath(child: 421, responsible: other), "/read/600")
        XCTAssertEqual(try responsiblePath(child: 422, responsible: other), "/read/600")
        XCTAssertEqual(reads, [600])
    }
    
    /// Events that create no process carry no launched-by parent at all.
    ///
    /// - Throws: An `XCTest` failure if an event wasn't serialized.
    func testOtherEventsHaveNone() throws {
        let exit = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        let open = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)
        open.message.pointee.event.open.file = open.file("/private/tmp/example")
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        for fixture in [exit, open] {
            let json = try XCTUnwrap(MessageSerializer(processPath: noPaths()).serialize(fixture.raw, in: lane))
            XCTAssertFalse(String(decoding: json, as: UTF8.self).contains("launched_by_parent"))
        }
    }
    
    /// Through a capture session, the process client's fork reaches `emit` stamped.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start, or the error decoding the event.
    func testThroughASession() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try CaptureSession(CaptureConfiguration(label: "Test"), clients: factory,
                                         serializer: MessageSerializer(processPath: noPaths()),
                                         sensorID: { "SENSOR" }, emit: emitted.append)
        session.isRecording = true
        factory.clients[0].deliver(shellFork())
        let event = try XCTUnwrap(emitted.all.first)
        XCTAssertEqual(event.eventClass, .process)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: event.json).createdLaunchedByParent, shellAnswer)
    }
    
    /// A message with a launched-by parent, named or not, streams exactly as `JSONEncoder` writes it.
    ///
    /// - Throws: The error reading the exec record, or an encoder's error.
    func testStreamsLikeJSONEncoder() throws {
        let unnamed = LaunchedByParent(source: .launchServices, audit_token: nil, path: nil, resolved_by: .app)
        let job = LaunchedByParent(source: .launchdJob, audit_token: .fixture(pid: 1, pidversion: 1),
                                   path: LaunchedByParent.launchdPath, launchd_job: .init(label: "com.example.agent"),
                                   resolved_by: .securityExtension)
        let fork = Message(from: shellFork().raw)
        let exec = try importRecord(try esloggerExec(parent: (1, 1), env: ["XPC_SERVICE_NAME=com.example.agent"]))
        let encoder = StreamingJSONEncoder()
        for (base, name) in [(fork, "fork"), (exec, "exec")] {
            for launchedByParent in [shellAnswer, unnamed, job] {
                var message = base
                message.setLaunchedByParent(launchedByParent)
                let streamed = try encoder.encode(message)
                XCTAssertFalse(encoder.state.pointee.isUnstreamable, name)
                XCTAssertEqual(try JSONCanonicalForm.canonical(streamed),
                               try JSONCanonicalForm.canonical(try JSONEncoder().encode(message)), name)
                XCTAssertEqual(try JSONDecoder().decode(Message.self, from: streamed).createdLaunchedByParent,
                               launchedByParent)
            }
        }
    }
    
    /// An exec (read from eslogger's JSON: a test can't build one from a raw message) gets its answer from the same
    /// resolution, and keeps the answer it has.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if it isn't an exec.
    func testExecIsResolvedOnce() throws {
        var exec = try importRecord(try esloggerExec(parent: (401, 4010), env: ["XPC_SERVICE_NAME=com.example.agent"]))
        XCTAssertNil(exec.createdLaunchedByParent, "eslogger's exec carries none")
        exec.resolveLaunchedByParent(by: .securityExtension) { pid, _ in "/path/of/\(pid)" }
        let shell = AuditToken(pid: 401, pidversion: 4010, asid: 100_001, auid: 4_294_967_295, euid: 0, ruid: 0,
                               rgid: 0, egid: 0)
        let expected = LaunchedByParent(source: .unixParent, audit_token: shell, path: "/path/of/401",
                                        resolved_by: .securityExtension)
        XCTAssertEqual(exec.createdLaunchedByParent, expected)
        exec.resolveLaunchedByParent(by: .app, path: noPaths())
        XCTAssertEqual(exec.createdLaunchedByParent, expected)
        
        var exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        exit.resolveLaunchedByParent(by: .securityExtension, path: noPaths())
        XCTAssertNil(exit.createdLaunchedByParent)
    }
    
    /// A direct launchd child names its job only when launchd's `xpcproxy` exec'd it: a job's program that execs
    /// again, or a copy of `xpcproxy` that isn't a platform binary, set the label themselves.
    ///
    /// - Throws: The error reading the record.
    func testOnlyXPCProxyNamesAJob() throws {
        let record = try esloggerExec(parent: (1, 1), env: ["XPC_SERVICE_NAME=com.example.agent"])
        let execs = [(try execedByXPCProxy(record), true), (record, false),
                     (try execedByXPCProxy(record, platform: false), false)]
        for (made, namesJob) in execs {
            var exec = try importRecord(made)
            exec.resolveLaunchedByParent(by: .securityExtension, path: noPaths())
            let answer = try XCTUnwrap(exec.createdLaunchedByParent)
            XCTAssertEqual(answer.source, namesJob ? .launchdJob : .unixParent)
            XCTAssertEqual(answer.launchd_job?.label, namesJob ? "com.example.agent" : nil)
            XCTAssertTrue(answer.isLaunchd)
        }
    }
}
