//
//  EnvironmentComparison.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/27/26.
//

import Foundation


// MARK: - Environment comparison
/// An exec's environment compared with its launcher's: the environment the nearest ancestor that exec'd had at its own
/// exec. A variable differs when the launcher had no variable of its name, or had another value. The launcher's first
/// variable of a name is the one compared.
///
/// PWD, OLDPWD, SHLVL and _ never differ: shells set them for each command.
public struct EnvironmentComparison {
    /// The names shells set for each command, which never differ and are never unset.
    static let shellNames: Set<String> = ["PWD", "OLDPWD", "SHLVL", "_"]

    /// The launcher, named by its executable and pid: `git (38070)`.
    public let launcher: String
    /// How many variables the exec has.
    public let count: Int
    /// The positions of the exec's variables that differ (``EnvironmentVariable/id``).
    public let differing: Set<Int>
    /// The names the launcher had and the exec doesn't, once each, in the launcher's order. The names shells set are
    /// left out.
    public let unset: [String]

    /// - Parameters:
    ///   - variables: The exec's variables, in order.
    ///   - launcher: The launcher, named by its executable and pid.
    ///   - baseline: The launcher's variables at its own exec, in order.
    public init(_ variables: [EnvironmentVariable], launcher: String, baseline: [EnvironmentVariable]) {
        let values = Dictionary(baseline.map { ($0.name, $0.value) }) { first, _ in first }
        self.launcher = launcher
        count = variables.count
        differing = Set(variables.filter { !Self.shellNames.contains($0.name) && values[$0.name] != $0.value }
            .map(\.id))
        /// The exec's names and the shells' are listed already, and each unset name is listed once.
        var listed = Set(variables.map(\.name)).union(Self.shellNames)
        unset = baseline.map(\.name).filter { listed.insert($0).inserted }
    }

    /// Does a variable of the exec differ from the launcher's?
    ///
    /// - Parameter variable: One of the exec's variables.
    /// - Returns: `true` when the launcher had no variable of its name or had another value.
    public func differs(_ variable: EnvironmentVariable) -> Bool {
        differing.contains(variable.id)
    }

    /// The comparison in a few words: `4 differ from git (38070)`, or `same as git (38070)`.
    public var reading: String {
        switch differing.count {
        case 0: "same as \(launcher)"
        case 1: "1 differs from \(launcher)"
        case let differ: "\(differ.formatted()) differ from \(launcher)"
        }
    }

    /// What the reading compares, the names it doesn't count, and the names the exec doesn't have.
    public var help: String {
        let compared = "Compared with the environment \(launcher) had at its own exec. PWD, OLDPWD, SHLVL and _ aren't "
            + "counted: shells set them for each command."
        guard !unset.isEmpty else { return compared }
        return compared + " \(unset.count.formatted()) unset: \(unset.joined(separator: ", "))."
    }

    /// How many variables don't differ: `19 the same as when git (38070) started`.
    public var same: String {
        "\((count - differing.count).formatted()) the same as when \(launcher) started"
    }
}


// MARK: - From the store
extension EnvironmentComparison {
    /// An exec's variables compared with its launcher's exec, as the store keeps it.
    ///
    /// - Parameters:
    ///   - variables: The exec's variables, in order.
    ///   - launcherExec: The launcher's exec (``CoreDataController/launcherExec(of:)``), on its context's queue.
    /// - Returns: The comparison, or `nil` without a launcher's exec.
    public init?(_ variables: [EnvironmentVariable], launcherExec: ESMessage?) {
        guard let exec = launcherExec?.event.exec else { return nil }
        let name = (exec.target.executable?.path ?? "").lastPathComponent
        self.init(variables, launcher: "\(name) (\(exec.target.pid))",
                  baseline: EnvironmentVariable.variables(in: exec.env))
    }
}
