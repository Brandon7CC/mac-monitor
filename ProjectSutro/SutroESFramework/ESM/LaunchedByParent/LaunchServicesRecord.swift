//
//  LaunchServicesRecord.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - LaunchServices record
/// What LaunchServices knows about an app it launched: which process checked in, and who asked for the launch.
///
/// An app checks in with LaunchServices only once its own code runs, 2-5 ms after Endpoint Security reports its exec,
/// so the Security Extension can't read this as it handles the exec. Mac Monitor reads it after the event arrives
/// (``LaunchedByParentUpgrader``), in the console user's audit session, through a ``LaunchServicesReading``.
public struct LaunchServicesRecord: Hashable {
    /// `LSAuditToken`: the process that checked in. Its pid version tells this launch apart from a reused pid.
    public var token: AuditToken
    /// `LSLaunchedByLaunchServices`: did LaunchServices launch it?
    public var launchedByLaunchServices: Bool
    /// Does the record name a launcher (`LSParentASN`), whether or not LaunchServices still has the launcher's record?
    public var hasParentASN: Bool
    /// The `LSAuditToken` of the launcher `LSParentASN` names: the process that asked for the launch. `nil` without
    /// one, and once LaunchServices no longer has the launcher's record. It keeps that record a while after the
    /// launcher quits (40 s and more), so the launcher may be gone.
    public var parentToken: AuditToken?
    /// The launcher's executable, from its own record (`CFBundleExecutablePath`), which outlives the launcher: its
    /// pid can't name it once it quits. `nil` without the launcher's record, or a path in it.
    public var parentPath: String?
    
    /// - Parameters:
    ///   - token: The process that checked in.
    ///   - launchedByLaunchServices: Did LaunchServices launch it?
    ///   - hasParentASN: Does the record name a launcher?
    ///   - parentToken: The launcher, when LaunchServices can still read its record.
    ///   - parentPath: The launcher's executable, from its record.
    public init(token: AuditToken, launchedByLaunchServices: Bool, hasParentASN: Bool, parentToken: AuditToken?,
                parentPath: String? = nil) {
        self.token = token
        self.launchedByLaunchServices = launchedByLaunchServices
        self.hasParentASN = hasParentASN
        self.parentToken = parentToken
        self.parentPath = parentPath
    }
}


// MARK: - Reading records
/// Reads LaunchServices' records of the apps it launched.
///
/// Mac Monitor's reader uses LaunchServices' private calls, so it lives in the app alone: the Security Extension never
/// contains or resolves them.
public protocol LaunchServicesReading: AnyObject {
    /// LaunchServices' record of a process, in the caller's audit session.
    ///
    /// - Parameter pid: The process's pid.
    /// - Returns: The record, or `nil` when there's none yet (the app hasn't checked in), none any more, or it can't
    ///   be read.
    func record(forPID pid: pid_t) -> LaunchServicesRecord?
}


// MARK: - LSAuditToken
extension AuditToken {
    /// A token from an `LSAuditToken` value, with the zeroed `id` a ``LaunchedByParent`` stores its token with.
    ///
    /// - Parameter data: The value: `audit_token_t`'s 32 bytes.
    /// - Returns: `nil` when the value isn't 32 bytes.
    public init?(auditTokenData data: Data) {
        guard data.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = data.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        self.init(pid: token.pid(), pidversion: token.pidversion(), asid: token.asid(), auid: token.auid(),
                  euid: token.euid(), ruid: token.ruid(), rgid: token.rgid(), egid: token.egid())
    }
}


// MARK: - Upgrading an answer
extension LaunchedByParent {
    /// This answer, improved with LaunchServices' record of the launch: the process that asked LaunchServices to
    /// launch the app (``Source/launchServices``), which comes before the responsible process.
    ///
    /// Only an answer that ``needsLaunchServices`` is improved, and only by a record of exactly this exec (its pid and
    /// pid version), so a reused pid can't lend another launch's launcher. The launchd job's label is kept.
    ///
    /// - A record that names a launcher gives that launcher, unless it's the target itself, named by the path its own
    ///   record holds: the launcher may have quit by now.
    /// - A record that names a launcher LaunchServices has forgotten gives nothing: the answer stays, rather than
    ///   claiming no launcher was recorded.
    /// - A launch that recorded no launcher (`open` from a shell) gives ``Source/launchServices`` with no process, in
    ///   place of a ``Source/launchdJob`` answer. A ``Source/responsibleProcess`` answer stays: it names a process.
    ///
    /// - Parameters:
    ///   - record: LaunchServices' record of the target's pid.
    ///   - target: The exec target's audit token.
    ///   - path: Names the launcher's executable from its pid and token when its record holds no path. A launcher that
    ///     has quit is named by nothing, or by whatever process reused its pid.
    /// - Returns: The improved answer, resolved by ``ResolvedBy/app``, or `nil` when the record doesn't improve this
    ///   one.
    func upgraded(with record: LaunchServicesRecord, for target: AuditToken,
                  path: (Int32, AuditToken?) -> String?) -> LaunchedByParent? {
        guard needsLaunchServices, record.token.isSameProcess(as: target) else { return nil }
        if let launcher = record.parentToken {
            guard launcher.pid > 0, !launcher.isSameProcess(as: target) else { return nil }
            return LaunchedByParent(source: .launchServices, audit_token: launcher,
                                    path: record.parentPath ?? path(launcher.pid, launcher), launchd_job: launchd_job,
                                    resolved_by: .app)
        }
        guard !record.hasParentASN, record.launchedByLaunchServices, source == .launchdJob else { return nil }
        return LaunchedByParent(source: .launchServices, audit_token: nil, pid: nil, path: nil,
                                launchd_job: launchd_job, resolved_by: .app)
    }
}
