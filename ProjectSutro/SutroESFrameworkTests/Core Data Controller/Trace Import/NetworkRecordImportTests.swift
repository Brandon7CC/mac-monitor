//
//  NetworkRecordImportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reading network records back
/// Pins how Open Trace reads a network flow's record: as the flow it was, named from its event's key, with its
/// process's values as the record has them rather than worked out again, so it exports the same bytes.
final class NetworkRecordImportTests: XCTestCase {
    /// Every network record of the corpus reads back as its flow, and exports the same bytes again.
    func testRecordsImportAndExportTheSame() throws {
        let messages = SyntheticCorpus.networkRecords().map(\.message)
        XCTAssertGreaterThan(messages.count, 10)
        for message in messages {
            let exported = exportText(message)
            let imported = try TraceImporter.message(from: Data(exported.utf8))
            let label = message.context ?? ""
            XCTAssertEqual(imported.event.macMonitorEvent, message.event.macMonitorEvent, label)
            XCTAssertEqual(imported.event_type, message.event_type, label)
            XCTAssertEqual(imported.es_event_type, message.es_event_type, label)
            XCTAssertEqual(imported.message_darwin_time.timeIntervalSince1970,
                           message.message_darwin_time.timeIntervalSince1970, accuracy: 1e-6, label)
            XCTAssertEqual(exportText(imported), exported, label)
        }
    }

    /// A flow's process keeps the code signing type its record names, which its zero code signing flags would
    /// otherwise make unsigned, and a pid, group or session the record leaves out stays unread.
    func testTheProcessIsReadAsTheRecordHasIt() throws {
        let live = try TraceImporter.message(from: Data(exportText(SyntheticFlows.message(
            SyntheticFlows.record(.opened))).utf8))
        XCTAssertEqual(live.process.codesigning_type, .platform)
        XCTAssertEqual(live.process.signing_id, "com.apple.nscurl")
        XCTAssertEqual(live.process.group_id, 753)
        XCTAssertEqual(live.process.audit_token?.pidversion, 2_341)
        let reaped = SyntheticFlows.record(.opened, process: SyntheticFlows.process(state: .reaped))
        let unread = try TraceImporter.message(from: Data(exportText(SyntheticFlows.message(reaped)).utf8))
        XCTAssertEqual([unread.process.ppid, unread.process.group_id, unread.process.session_id],
                       [Process.unread, Process.unread, Process.unread])
        XCTAssertEqual(unread.process.codesigning_type, .unknown)
        XCTAssertNil(unread.process.executable)
    }
}
