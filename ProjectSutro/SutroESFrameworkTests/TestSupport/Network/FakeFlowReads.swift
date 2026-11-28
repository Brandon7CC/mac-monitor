//
//  FakeFlowReads.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Fake process reads
/// The processes a flow's resolver reads, made up by a test: live, zombie or gone, and a process that execs between
/// two reads. Counts what's read.
final class FakeFlowReads {
    /// One process.
    struct Process {
        var upid: UInt64
        var pidversion: Int32
        var ppid: Int32 = 1, groupID: Int32 = 0, sessionID: Int32 = 0
        var isZombie = false
        var path = "/usr/bin/curl"
        var signing: FlowSigning? = FlowSigning(signingID: "com.apple.curl", teamID: nil, type: .platform)
        /// The pid version its token has, when it exec'd after its identity was read.
        var tokenVersion: Int32?
    }

    /// The processes by pid.
    var processes: [Int32: Process] = [:]
    /// What the lineage table knows.
    var programs: [ProcessKey: ProcessProgram] = [:]
    /// How many identity and signing reads were made.
    private(set) var identityReads = 0, signingReads = 0

    /// The reads, for a resolver.
    var reads: FlowProcessResolver.Reads {
        FlowProcessResolver.Reads(identity: { [self] pid in
            identityReads += 1
            return processes[pid].map { ($0.upid, $0.pidversion) }
        }, bsd: { [self] pid in
            processes[pid].map { ($0.ppid, $0.groupID, $0.isZombie) }
        }, session: { [self] pid in
            processes[pid].flatMap { $0.isZombie ? nil : $0.sessionID }
        }, token: { [self] pid in
            guard let process = processes[pid], !process.isZombie else { return nil }
            let version = process.tokenVersion ?? process.pidversion
            return RawMessageFixture.auditToken(pid: pid, pidversion: UInt32(version))
        }, path: { [self] token in
            processes[ProcessKey(token).pid]?.path
        }, signing: { [self] token, _ in
            signingReads += 1
            return processes[ProcessKey(token).pid]?.signing
        }, program: { [self] key in
            programs[key]
        })
    }
}
