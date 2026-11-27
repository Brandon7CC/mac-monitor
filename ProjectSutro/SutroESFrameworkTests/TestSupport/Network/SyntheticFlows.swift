//
//  SyntheticFlows.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Flow records for tests
/// Flow records as the network statistics client hands them to a session, made up from the test VMs' kind of
/// values: nscurl connecting to Wikipedia from 192.168.64.2, and mDNSResponder looking a name up for it.
enum SyntheticFlows {
    /// When the flow was seen, in nanoseconds since 1970: the synthetic corpus's time.
    static let wall: Int64 = 1_791_201_600_123_456_789
    /// When its socket was made: 3.5 ms before.
    static let start: Int64 = wall - 3_500_000
    /// The flow's time on Endpoint Security's clock.
    static let machTime: Int64 = 24_873_120_451
    /// The flow's identifier.
    static let identifier = UUID(uuidString: "5C1F0E2A-9B7D-4E33-8A61-0D2C4B6E8F10")!

    /// An audit token: root, in audit session 100003.
    ///
    /// - Parameters:
    ///   - pid: The pid.
    ///   - pidversion: The pid version.
    /// - Returns: The token.
    static func token(pid: Int32, pidversion: Int32) -> audit_token_t {
        audit_token_t(val: (501, 0, 0, 0, 0, UInt32(bitPattern: pid), 100_003, UInt32(bitPattern: pidversion)))
    }

    /// A flow's process.
    ///
    /// - Parameters:
    ///   - pid: Its pid.
    ///   - path: Its executable.
    ///   - signingID: Its signing ID.
    ///   - state: What it was at its socket's first update: `live` has everything, `zombie` no session, and
    ///     `reaped` no token, program, parent or group.
    /// - Returns: The process.
    static func process(pid: Int32 = 753, path: String = "/usr/bin/nscurl", signingID: String = "com.apple.nscurl",
                        state: FlowProcess.State = .live) -> FlowProcess {
        let key = ProcessKey(pid: pid, pidversion: 2_341)
        let known = state != .reaped
        return FlowProcess(pid: pid, name: path.lastPathComponent, state: state, key: known ? key : nil,
                           token: known ? token(pid: pid, pidversion: 2_341) : nil,
                           program: known ? ProcessProgram(key: key, path: path, signingID: signingID,
                                                           teamID: "SYNTHETIC1", codesigningType: "PLATFORM") : nil,
                           ppid: known ? 512 : nil, groupID: known ? pid : nil,
                           sessionID: state == .live ? 512 : nil)
    }

    /// A flow that opened or closed.
    ///
    /// - Parameters:
    ///   - kind: Opened or closed.
    ///   - process: Its process.
    ///   - sourceApp: The app its socket acts for.
    ///   - minimal: Leave out everything the kernel may not give: the local end, hostname, URL, first-party site
    ///     and direction.
    ///   - counted: Did a closed flow's final counts come?
    ///   - url: Its URL, with its path.
    ///   - start: When its socket was made.
    /// - Returns: The record.
    static func record(_ kind: FlowRecord.Kind, process: FlowProcess = process(), sourceApp: FlowProcess? = nil,
                       minimal: Bool = false, counted: Bool = true,
                       url: String = "https://en.wikipedia.org/wiki/Endpoint_security",
                       start: Int64 = SyntheticFlows.start) -> FlowRecord {
        let closed = kind == .closed && counted
        return FlowRecord(kind: kind, identifier: identifier, process: process, sourceApp: sourceApp, isOwn: false,
                          local: minimal ? nil : FlowEndpoint(address: "192.168.64.2", port: 49_310),
                          remote: FlowEndpoint(address: "198.35.26.224", port: 443), family: AF_INET,
                          type: SOCK_STREAM, proto: IPPROTO_TCP, hostname: minimal ? nil : "en.wikipedia.org",
                          url: minimal ? nil : url, firstPartySite: minimal ? nil : "wikipedia.org",
                          direction: minimal ? nil : .outbound, start: start,
                          time: FlowTime(machTime: machTime, wall: wall), bytesIn: closed ? 36_385 : nil,
                          bytesOut: closed ? 3_059 : nil)
    }

    /// A flow's message, as a session makes it.
    ///
    /// - Parameters:
    ///   - record: The flow.
    ///   - keepingURLPath: Keep the URL's path?
    ///   - sipStatus: System Integrity Protection's status, or `nil` when it couldn't be read.
    ///   - bootSession: The boot session's identifier, or `nil` when it couldn't be read.
    /// - Returns: The message.
    static func message(_ record: FlowRecord, keepingURLPath: Bool = true, sipStatus: SIPStatus? = .disabled,
                        bootSession: String? = SyntheticValues.uuid.uuidString) -> Message {
        Message(flow: record, keepingURLPath: keepingURLPath, sensorID: "SENSOR", macOS: "27.2 (Build 26B123)",
                sipStatus: sipStatus, bootSession: bootSession)
    }
}
