//
//  YaraScan.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - A written file's scan
/// What Mac Monitor found when it scanned a written file with Apple's XProtect rules: the `yara_scan` enrichment of a
/// modified close, and of the rename that moves such a file into place.
///
/// Only Mach-O executables, libraries and bundles, scripts and compiled AppleScript are scanned. Every file that
/// isn't scanned says why in ``status``. The rules are XProtect's own, from the XProtect bundle this Mac has, and the
/// names are XProtect's: a match is what XProtect's rules say of the file, not a verdict of Mac Monitor's.
public struct YaraScan: Codable, Hashable, Sendable {
    /// The file was scanned. ``rules`` lists what matched, if anything.
    public static let scanned = "scanned"
    /// The file is larger than the most Mac Monitor scans.
    public static let tooLarge = "too_large"
    /// Scanning it would have spent more CPU than the scanner's share allows right now.
    public static let overBudget = "over_budget"
    /// The scanner couldn't have finished it in time, behind the files before it.
    public static let busy = "busy"
    /// The file couldn't be read: gone, dataless, or one the writer couldn't read.
    public static let unreadable = "unreadable"
    /// The file changed before it was read. The close of the change is scanned.
    public static let changed = "changed"
    /// Apple's rules couldn't be used on this Mac.
    public static let unavailable = "unavailable"
    /// The scan ran past its time.
    public static let timedOut = "timed_out"
    /// So many strings matched that libyara stopped the scan.
    public static let tooManyMatches = "too_many_matches"

    /// The name Settings turns scanning on and off by, beside the event names Mac Monitor subscribes to
    /// (``SensorService``'s `setSubscription(_:enabled:reply:)`).
    public static let subscriptionName = "yara_scan"

    /// Whether it was scanned, or why not: one of the values above.
    public var status: String
    /// The XProtect version whose rules scanned it, such as `5377`. `nil` when no rules were loaded.
    public var xprotect_version: String?
    /// Every rule that matched, by its identifier, such as `XProtect_MACOS_OSASCRIPT_BOZO`.
    public var rules: [String]
    /// XProtect's name for each rule in ``rules``, in the same order, such as `MACOS.OSASCRIPT.BOZO`. A rule without
    /// one is named by its identifier.
    public var names: [String]
    /// The rules in ``rules`` XProtect only reports and never acts on (`match_type = 4`), such as Apple's hunting
    /// rules.
    public var report_only: [String]

    /// - Parameters:
    ///   - status: Whether it was scanned, or why not.
    ///   - xprotectVersion: The XProtect version whose rules scanned it.
    ///   - matches: The rules that matched.
    init(status: String, xprotectVersion: String? = nil, matches: [YaraMatch] = []) {
        self.status = status
        xprotect_version = xprotectVersion
        rules = matches.map(\.identifier)
        names = matches.map { $0.name ?? $0.identifier }
        report_only = matches.filter(\.isReportOnly).map(\.identifier)
    }

    /// Every key, `xprotect_version` too when it's `null`, as the schema has them.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(status, forKey: .status)
        try container.encode(xprotect_version, forKey: .xprotect_version)
        try container.encode(rules, forKey: .rules)
        try container.encode(names, forKey: .names)
        try container.encode(report_only, forKey: .report_only)
    }

    /// A file that wasn't scanned, and why.
    ///
    /// - Parameters:
    ///   - reason: One of the statuses other than ``scanned``.
    ///   - xprotectVersion: The XProtect version loaded, if any.
    /// - Returns: The scan.
    static func notScanned(_ reason: String, xprotectVersion: String? = nil) -> YaraScan {
        YaraScan(status: reason, xprotectVersion: xprotectVersion)
    }

    /// Does the result say something of the file's content: scanned, or so many strings matched that libyara
    /// stopped? Only such a result answers an exec that looks the file up by its content
    /// (``FileScanMemory/result(for:covering:anyChangeTime:)``).
    var describesContent: Bool {
        status == Self.scanned || status == Self.tooManyMatches
    }
}


// MARK: - Storing a scan
extension YaraScan {
    /// The scan as JSON, as the app's store keeps it.
    var encoded: Data? { try? JSONEncoder().encode(self) }

    /// A scan the app's store kept.
    ///
    /// - Parameter data: Its JSON.
    /// - Returns: The scan, or `nil` for none or JSON that isn't one.
    static func decoded(from data: Data?) -> YaraScan? {
        data.flatMap { try? JSONDecoder().decode(YaraScan.self, from: $0) }
    }
}
