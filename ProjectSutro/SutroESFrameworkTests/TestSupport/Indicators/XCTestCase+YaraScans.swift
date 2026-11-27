//
//  XCTestCase+YaraScans.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Written files' scans
extension XCTestCase {
    /// A rule on a written file's scan that matched any XProtect rule, on a close or on a rename. It needs Mac
    /// Monitor 3.3.0, which added `yara_scan`.
    static let yaraRulePredicate = #"(event.close != nil AND ANY event.close.yara_scan.rules != "") OR "#
        + #"(event.rename != nil AND ANY event.rename.yara_scan.rules != "")"#

    /// The release after this build's engine. An indicator or a pack that needs it isn't run here.
    static var laterEngine: ReleaseVersion {
        ReleaseVersion(Indicator.engineVersion.major, Indicator.engineVersion.minor, Indicator.engineVersion.patch + 1)
    }

    /// The XProtect rule ``matchedScan`` found.
    static let matchedRule = "XProtect_MACOS_OSASCRIPT_BOZO"

    /// A scan of a written file that matched one of XProtect's rules.
    static let matchedScan = YaraScan(status: YaraScan.scanned, xprotectVersion: "5377",
                                      matches: [YaraMatch(identifier: matchedRule, name: "MACOS.OSASCRIPT.BOZO",
                                                          matchType: 11)])

    /// Scans whose arrays differ in size, for rules that count them: none, one that didn't run, ``matchedScan``, and
    /// three rules, two of which XProtect only reports.
    static let countedScans: [YaraScan?] = [nil, YaraScan.notScanned(YaraScan.busy), matchedScan,
                                            YaraScan(status: YaraScan.scanned, xprotectVersion: "5377", matches: [
                                                YaraMatch(identifier: "XProtect_A", name: "A", matchType: 11),
                                                YaraMatch(identifier: "XProtect_B", name: nil, matchType: 0),
                                                YaraMatch(identifier: "XProtect_C", name: "C", matchType: 0),
                                            ])]

    /// The synthetic corpus's close, rename and exec with each of ``countedScans``, read back from their export
    /// records.
    ///
    /// - Returns: The closes, then the renames, then the execs.
    /// - Throws: The error making up the corpus or reading a record.
    func countedScanMessages() throws -> [Message] {
        try ["ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_RENAME", "ES_EVENT_TYPE_NOTIFY_EXEC"].flatMap { type in
            try Self.countedScans.map { try TraceImporter.message(from: try scannedRecord(type, scan: $0)) }
        }
    }

    /// The synthetic corpus's full close, rename or exec, with a scan or none, as Export telemetry writes its record.
    ///
    /// - Parameters:
    ///   - type: Its type, `ES_EVENT_TYPE_NOTIFY_CLOSE`, `ES_EVENT_TYPE_NOTIFY_RENAME` or `ES_EVENT_TYPE_NOTIFY_EXEC`.
    ///   - scan: Its scan, or `nil` for none.
    /// - Returns: The record and a newline.
    /// - Throws: The error making up the corpus, or a failure when it has no such event.
    func scannedRecord(_ type: String, scan: YaraScan? = matchedScan) throws -> Data {
        XCTAssertTrue(["ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_RENAME", "ES_EVENT_TYPE_NOTIFY_EXEC"]
            .contains(type), "\(type) has no scan")
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message).first { $0.es_event_type == type }, type)
        message.setYaraScan(scan)
        return ExportEncoder(model: try XCTUnwrap(ExportEncoder.model)).line(for: message)
    }
}
