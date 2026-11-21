//
//  UpdateCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - Invocation
/// `macmonitor update check [--json]`.
public struct UpdateInvocation: Equatable {
    /// Write JSON, for a script, rather than text? `--json`.
    public var json: Bool

    /// - Parameter json: Write JSON rather than text?
    public init(json: Bool = false) {
        self.json = json
    }
}


// MARK: - Report
/// What `macmonitor update check` shows: whether a Mac Monitor release newer than the one running is out.
///
/// The Security Extension looks the latest release up on GitHub itself, as it does for Mac Monitor's Check for
/// Updates (``ReleaseChoice``), so nothing about the release comes from `macmonitor`. Nothing is installed: Mac
/// Monitor installs a release.
public struct UpdateReport: Encodable, Equatable {
    /// Is a newer release out?
    public var available: Bool
    /// The version running, such as "3.2.0".
    public var current: String
    /// The newer release's version, such as "3.2.1", or `nil` when there's none.
    public var latest: String?
    /// When the newer release was published, as GitHub gives it, or `nil`.
    public var published: String?
    /// The newer release's page on GitHub, or `nil`.
    public var url: String?

    /// Read the Security Extension's answer to an update check.
    ///
    /// - Parameter answer: Its answer, or why there's none.
    /// - Returns: The report, or the failure: 69 when the Security Extension isn't there, is older than 3.2, or is a
    ///   build that doesn't update itself, and 75 when GitHub couldn't be reached or its answer couldn't be read.
    public static func read(_ answer: Result<StreamReply, CommandLineFailure>)
        -> Result<UpdateReport, CommandLineFailure> {
        let reply: StreamReply
        switch answer {
        case .failure(let failure): return .failure(failure)
        case .success(let answered): reply = answered
        }
        /// The Security Extension's version is such as "3.2.0 (145)".
        let current = String(reply.sensorVersion.prefix { $0 != " " })
        /// One older than 3.2 doesn't know the request, and refuses it from a caller that may not stream rather than
        /// say so.
        if reply.status == .refused, let version = ReleaseVersion(current), version < ReleaseVersion(3, 2, 0) {
            return .failure(.olderSecurityExtension)
        }
        if let failure = CommandLineFailure.reply(reply) { return .failure(failure) }
        switch reply.update {
        case nil:
            return .failure(CommandLineFailure(.unavailable, """
                This Mac Monitor doesn't check for updates: it's a Community build.
                """))
        case .failed?:
            return .failure(CommandLineFailure(.temporaryFailure, """
                GitHub couldn't be reached, or its answer couldn't be read. Try again later.
                """))
        case .upToDate?:
            return .success(UpdateReport(available: false, current: current))
        case .newer(let release)?:
            return .success(UpdateReport(available: true, current: current, latest: release.number,
                                         published: release.releaseDate, url: ReleaseChoice.page(of: release.version)))
        }
    }

    /// Every key, with `null` for what there isn't, so a script always finds the same keys.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When a value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(available, forKey: .available)
        try container.encode(current, forKey: .current)
        try container.encode(latest, forKey: .latest)
        try container.encode(published, forKey: .published)
        try container.encode(url, forKey: .url)
    }

    private enum CodingKeys: String, CodingKey {
        case available, current, latest, published, url
    }
}


// MARK: - Writing
/// Writes an ``UpdateReport`` as text or JSON.
public enum UpdateCommand {
    /// - Parameters:
    ///   - report: The report.
    ///   - json: Write JSON rather than text?
    /// - Returns: What `macmonitor update check` prints, ending in a newline.
    public static func output(_ report: UpdateReport, json: Bool) -> String {
        guard json else { return text(report) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(report)) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self) + "\n"
    }

    /// - Parameter report: The report.
    /// - Returns: It as text: that this is the latest release, or the newer one, its page and how to install it.
    static func text(_ report: UpdateReport) -> String {
        guard report.available, let latest = report.latest else {
            return "Mac Monitor \(TerminalSafeText.text(report.current)) is the latest release.\n"
        }
        let lines = ["Mac Monitor \(latest) is out. This Mac has \(report.current).", report.url,
                     "Open Mac Monitor and choose Check for Updates to install it."]
        return lines.compactMap { $0 }.map(TerminalSafeText.text).joined(separator: "\n") + "\n"
    }
}
