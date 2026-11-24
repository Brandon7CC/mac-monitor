//
//  ProcessKey.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Process keys
/// One program a process ran: its pid and pid version. An exec keeps the pid and raises the version, so a pid that
/// ran three programs in a row has three keys, and a pid the system used again has another.
public struct ProcessKey: Hashable, Sendable, CustomStringConvertible {
    /// The process's pid.
    public let pid: Int32
    /// The pid's version, which every exec raises.
    public let pidversion: Int32

    /// launchd's pid, which every chain of parents ends at.
    static let launchd: Int32 = 1

    /// - Parameters:
    ///   - pid: The process's pid.
    ///   - pidversion: The pid's version.
    public init(pid: Int32, pidversion: Int32) {
        self.pid = pid
        self.pidversion = pidversion
    }

    /// - Parameter token: A process's audit token.
    public init(_ token: AuditToken) {
        self.init(pid: token.pid, pidversion: token.pidversion)
    }

    /// - Parameter text: A key as a record writes it, such as `43372.103226`.
    public init?(_ text: some StringProtocol) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, let pid = Int32(parts[0]), let pidversion = Int32(parts[1]), pid >= 0,
              pidversion >= 0 else { return nil }
        self.init(pid: pid, pidversion: pidversion)
    }

    /// The key as a record writes it: the pid, a dot, and the pid version.
    public var description: String {
        "\(pid).\(pidversion)"
    }

    /// Is it launchd, or the kernel? Neither is listed as an ancestor: every process descends from them.
    var isRoot: Bool {
        pid <= Self.launchd
    }
}


// MARK: - A program
/// What the Security Extension keeps about one program a process ran, for the indicators that ask about a process's
/// ancestors. Each value is the one the program's own exec record has.
public struct ProcessProgram: Equatable, Sendable {
    /// Which program of which process.
    public var key: ProcessKey
    /// Its executable's path. `nil` for a process that's only known as someone's parent.
    public var path: String?
    /// Its command line, as its exec record has it, up to ``commandLineLimit``: the table keeps one for every
    /// process, and a compiler's can run to tens of kilobytes.
    public var commandLine: String?
    /// Its signing ID.
    public var signingID: String?
    /// Its team ID.
    public var teamID: String?
    /// How it's signed, as a record's `codesigning_type` says it.
    public var codesigningType: String?

    /// - Parameters:
    ///   - key: Which program of which process.
    ///   - path: Its executable's path.
    ///   - commandLine: Its command line.
    ///   - signingID: Its signing ID.
    ///   - teamID: Its team ID.
    ///   - codesigningType: How it's signed.
    public init(key: ProcessKey, path: String? = nil, commandLine: String? = nil, signingID: String? = nil,
                teamID: String? = nil, codesigningType: String? = nil) {
        self.key = key
        self.path = path
        self.commandLine = commandLine.map { line in
            line.utf8.count <= Self.commandLineLimit ? line
                : String(String.UnicodeScalarView(line.unicodeScalars.prefix(Self.commandLineLimit)))
        }
        self.signingID = signingID
        self.teamID = teamID
        self.codesigningType = codesigningType
    }

    /// The most of a command line that's kept, in characters. A longer one is cut short.
    public static let commandLineLimit = 1_024

    /// Is anything known of it but its key?
    var isKnown: Bool {
        path != nil
    }
}
