//
//  LaunchedByParentUpgrader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launched-by parent upgrader
/// Asks Launch Services who launched an app the Security Extension saw exec'd.
///
/// An app checks in with Launch Services 2-5 ms after its exec, so the record isn't there yet when we handle the exec.
/// We read it at each of ``delays`` instead. By default that's right away, then 50 ms and 250 ms later. The first
/// record we find ends the lookup. If it's for this exact exec and names a better launched-by parent, we hand that
/// back (``LaunchedByParent/upgraded(with:for:path:)``).
///
/// ``LaunchServicesHold`` holds the exec until the lookup ends. Lookups run on the upgrader's own queue, never on a
/// handler queue.
final class LaunchedByParentUpgrader {
    /// When we read an app's record, in seconds after the lookup starts
    static let defaultDelays: [TimeInterval] = [0, 0.05, 0.25]

    /// Reads Launch Services' records
    let reader: LaunchServicesReading
    /// When we read an app's record, in seconds after the lookup starts
    let delays: [TimeInterval]
    /// Finds a launcher's executable from its pid and token when the record has no path
    private let path: (Int32, AuditToken?) -> String?
    /// The queue lookups run on
    let queue = DispatchQueue(label: "com.swiftlydetecting.agent.launchedByParentUpgrader", qos: .utility)

    /// - Parameters:
    ///   - reader: Reads Launch Services' records.
    ///   - delays: When to read an app's record, in seconds after the lookup starts. There must be at least one.
    ///   - path: Finds a launcher's executable from its pid and token (``ProcessPath/live``).
    init(reader: LaunchServicesReading, delays: [TimeInterval] = LaunchedByParentUpgrader.defaultDelays,
         path: @escaping (Int32, AuditToken?) -> String? = ProcessPath.live) {
        precondition(!delays.isEmpty, "A lookup reads at least once")
        self.reader = reader
        self.delays = delays
        self.path = path
    }

    /// Look up who launched an exec's target.
    ///
    /// - Parameters:
    ///   - answer: The launched-by parent the exec has now. It must need Launch Services
    ///     (``LaunchedByParent/needsLaunchServices``).
    ///   - target: The exec target's audit token.
    ///   - completion: Called exactly once on ``queue``. It gets the better answer, or `nil` if Launch Services had
    ///     no record of this exec by the last read or the record doesn't improve on what we have.
    func lookUp(_ answer: LaunchedByParent, of target: AuditToken,
                completion: @escaping (LaunchedByParent?) -> Void) {
        read(answer, of: target, attempt: 0, startedAt: .now(), completion: completion)
    }

    /// Read the app's record after this attempt's delay, then finish or try again.
    ///
    /// - Parameters:
    ///   - answer: The launched-by parent the exec has now.
    ///   - target: The exec target's audit token.
    ///   - attempt: Which delay to read at.
    ///   - start: When the lookup started.
    ///   - completion: Gets the better answer, or `nil`.
    private func read(_ answer: LaunchedByParent, of target: AuditToken, attempt: Int, startedAt start: DispatchTime,
                      completion: @escaping (LaunchedByParent?) -> Void) {
        queue.asyncAfter(deadline: start + delays[attempt]) { [self] in
            guard let record = reader.record(forPID: target.pid) else {
                guard attempt + 1 < delays.count else { return completion(nil) }
                return read(answer, of: target, attempt: attempt + 1, startedAt: start, completion: completion)
            }
            /// An app's record doesn't change once it's there, so reading it again wouldn't help.
            completion(answer.upgraded(with: record, for: target, path: path))
        }
    }
}
