//
//  IndicatorTests+Records.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Records
/// The indicators an export record lists, and the search that reads the record.
extension IndicatorTests {
    /// An export record lists the indicators that are on and match it, in order, each with its tactic and technique,
    /// and `--indicator` writes an event only when its record lists one by that name, ignoring case. Without
    /// indicators the key is left out.
    func testRecordsListTheirIndicators() throws {
        let message = try XCTUnwrap(SyntheticCorpus.records().first).message
        var every = Indicator.defaults[0]
        every.predicate = "event_type >= 0"
        var off = every
        off.id = UUID()
        off.isEnabled = false
        let never = Indicator(name: "Never", description: "", symbol: "star", color: .red, predicate: "event_type < 0")
        let model = try XCTUnwrap(ExportEncoder.model)
        let line = ExportEncoder(model: model, indicators: [never, every, off]).line(for: message)
        let record = try XCTUnwrap(JSONSerialization.jsonObject(with: line) as? NSDictionary)
        let listed = try XCTUnwrap(record["indicators"] as? [[String: Any]])
        XCTAssertEqual(listed.map { $0["name"] as? String }, ["Reflective loading"])
        XCTAssertEqual(listed.first?["tactic"] as? String, "Defense Evasion")
        XCTAssertEqual(listed.first?["tactic_id"] as? String, "TA0005")
        XCTAssertEqual(listed.first?["technique"] as? String, "T1620")
        XCTAssertEqual(listed.first?["default"] as? Bool, true)
        let plain = ExportEncoder(model: model).line(for: message)
        XCTAssertNil((try JSONSerialization.jsonObject(with: plain) as? NSDictionary)?["indicators"])

        var filter = StreamFilter()
        filter.indicators = ["reflective LOADING"]
        XCTAssertTrue(filter.readsRecords)
        XCTAssertTrue(try filter.admits(record: record))
        filter.indicators = ["Never"]
        XCTAssertFalse(try filter.admits(record: record))
        guard case .stream(let stream) = try CommandLineParser.parse(["stream", "--indicator", "Plist modified",
                                                                      "--indicator=Login"]) else {
            return XCTFail("Not a stream")
        }
        XCTAssertEqual(stream.filter.indicators, ["Plist modified", "Login"])
        XCTAssertThrowsError(try CommandLineParser.parse(["stream", "--indicator", " "]))
    }

    /// The event tables' search reads the record Export telemetry writes. A predicate that names `indicators` sees
    /// exactly the exported record, every key, for every event of the synthetic corpus and the fixtures. One that
    /// doesn't sees it without `indicators`, and nothing else left out. A key exports add that the search can't see
    /// fails here, as `indicators` once did.
    func testSearchReadsTheExportedRecord() throws {
        let reading = try StreamFilter.Predicate(RecordIndicators.exampleQuery)
        let plain = try StreamFilter.Predicate("event_type >= 0")
        XCTAssertTrue(reading.readsIndicators)
        XCTAssertFalse(plain.readsIndicators)
        let exported = RecordIndicators(Indicator.defaults)
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            var listed = 0
            for event in stored {
                let export = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(
                    RecordIndicators.encoding(with: exported) { ProcessHelpers.eventToJSON(value: event) }.utf8))
                    as? NSDictionary)
                let searched = try reading.searching(indicators: Indicator.defaults) {
                    try StreamFilter.Predicate.record(of: event)
                }
                XCTAssertEqual(searched, export, event.es_event_type ?? "")
                let unread = try plain.searching(indicators: Indicator.defaults) {
                    try StreamFilter.Predicate.record(of: event)
                }
                let withoutIndicators = export.mutableCopy() as! NSMutableDictionary
                withoutIndicators.removeObject(forKey: "indicators")
                XCTAssertEqual(unread, withoutIndicators, event.es_event_type ?? "")
                listed += (export["indicators"] as? [Any])?.count ?? 0
            }
            XCTAssertGreaterThan(listed, 0)
        }
    }

    /// A predicate on an indicator's name, as the predicate editor's example is, finds exactly the events that
    /// indicator matches, for every indicator Mac Monitor ships, when the search gives it the indicators. Without
    /// them it finds none.
    func testIndicatorNamesFindTheirEvents() throws {
        XCTAssertTrue(Indicator.defaults.contains { RecordIndicators.exampleQuery.contains("\"\($0.name)\"") })
        let matcher = IndicatorMatcher(Indicator.defaults)
        let byName = try Indicator.defaults.map { indicator in
            (indicator, try StreamFilter.Predicate(#"ANY indicators.name ==[c] "\#(indicator.name.uppercased())""#))
        }
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            var found = 0
            for event in stored {
                let matched = Set(matcher.matches(event).map(\.id))
                for (indicator, predicate) in byName {
                    let hit = try predicate.searching(indicators: Indicator.defaults) {
                        try predicate.evaluate(on: event)
                    }
                    XCTAssertEqual(hit, matched.contains(indicator.id),
                                   "\(indicator.name) \(event.es_event_type ?? "")")
                    XCTAssertFalse(try predicate.evaluate(on: event), indicator.name)
                    found += hit ? 1 : 0
                }
            }
            XCTAssertGreaterThan(found, 0)
        }
    }
}
