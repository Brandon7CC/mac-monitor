//
//  LaunchedByParentUpgrader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launched-by parent upgrader
/// Asks Launch Services who launched an app.
///
/// Apps check in 2-5 ms after their exec, so we read the record at each of ``delays``.
final class LaunchedByParentUpgrader {
    static let defaultDelays: [TimeInterval] = [0, 0.05, 0.25]

    let reader: LaunchServicesReading
    /// Seconds after the lookup starts
    let delays: [TimeInterval]
    /// Used when the record has no path
    private let path: (Int32, AuditToken?) -> String?
    let queue = DispatchQueue(label: "com.swiftlydetecting.agent.launchedByParentUpgrader", qos: .utility)

    /// - Parameters:
    ///   - reader: Reads Launch Services' records.
    ///   - delays: When to read, in seconds. At least one.
    ///   - path: Finds a launcher's executable by pid.
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
    ///   - answer: The exec's current launched-by parent.
    ///   - target: The exec target's audit token.
    ///   - completion: Called once on ``queue`` with the better answer, or `nil`.
    func lookUp(_ answer: LaunchedByParent, of target: AuditToken,
                completion: @escaping (LaunchedByParent?) -> Void) {
        read(answer, of: target, attempt: 0, startedAt: .now(), completion: completion)
    }

    /// Read the record after this attempt's delay, then finish or retry.
    ///
    /// - Parameters:
    ///   - answer: The exec's current launched-by parent.
    ///   - target: The exec target's audit token.
    ///   - attempt: Which delay to use.
    ///   - start: When the lookup started.
    ///   - completion: Gets the better answer, or `nil`.
    private func read(_ answer: LaunchedByParent, of target: AuditToken, attempt: Int, startedAt start: DispatchTime,
                      completion: @escaping (LaunchedByParent?) -> Void) {
        queue.asyncAfter(deadline: start + delays[attempt]) { [self] in
            guard let record = reader.record(forPID: target.pid) else {
                guard attempt + 1 < delays.count else { return completion(nil) }
                return read(answer, of: target, attempt: attempt + 1, startedAt: start, completion: completion)
            }
            // The record doesn't change once it exists.
            completion(answer.upgraded(with: record, for: target, path: path))
        }
    }
}
