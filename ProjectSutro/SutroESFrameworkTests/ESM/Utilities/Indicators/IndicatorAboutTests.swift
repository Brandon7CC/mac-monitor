//
//  IndicatorAboutTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - About an indicator
/// Pins what Settings > Indicators says about an indicator: one Mac Monitor ships names its pack, revision and
/// whether this Mac changed it, one added here says so, and each lists the event types it runs on.
final class IndicatorAboutTests: XCTestCase {
    /// - Parameter about: What's said of an indicator.
    /// - Returns: Each fact's value, by its name.
    private func values(_ about: IndicatorAbout) -> [String: String] {
        Dictionary(about.rows.map { ($0.name, $0.value) }) { first, _ in first }
    }

    /// A shipped indicator names the pack it's from, as `Mac Monitor (Pack 1)` whether the build links the pack in
    /// or it was installed since, its revision, and that it's unchanged. Edited, it says so, and keeps the revision
    /// it was edited from.
    func testAShippedIndicatorNamesItsPack() throws {
        var shipped = ownIndicator("Ran a script", "event.exec != nil AND event.exec.script != nil")
        shipped.revision = 2
        shipped.minEngine = ReleaseVersion(3, 2, 0)
        let pack = IndicatorPackStatus(sequence: 1, source: .linked, published: "2026-11-18T02:56:37Z",
                                       commit: "fac2be06694c2c92266b58ea72efafc5eff8abdd")
        let about = IndicatorAbout(shipped, baseline: [shipped], pack: pack)
        XCTAssertEqual(about.identity, shipped.id.uuidString)
        XCTAssertEqual(about.summary, "Pack 1, revision 2")
        XCTAssertEqual(about.rows.map(\.name), ["ID", "Source", "Revision", "State", "Runs on", "Requires"])
        XCTAssertEqual(values(about), [
            "ID": shipped.id.uuidString, "Source": "Mac Monitor (Pack 1)",
            "Revision": "2", "State": "Unchanged", "Runs on": "exec", "Requires": "Mac Monitor 3.2.0 or later",
        ])
        var edited = shipped
        edited.severity = .high
        edited.isEnabled = false
        let installed = IndicatorPackStatus(sequence: 3, source: .installed)
        XCTAssertEqual(values(IndicatorAbout(edited, baseline: [shipped], pack: installed)), [
            "ID": shipped.id.uuidString, "Source": "Mac Monitor (Pack 3)", "Revision": "2",
            "State": "Edited on this Mac", "Runs on": "exec", "Requires": "Mac Monitor 3.2.0 or later",
        ])
        XCTAssertEqual(IndicatorAbout(edited, baseline: [shipped], pack: installed).summary,
                       "Pack 3, revision 2, edited")
        var off = shipped
        off.isEnabled = false
        XCTAssertEqual(IndicatorAbout(off, baseline: [shipped], pack: nil).summary, "Mac Monitor, revision 2")
        XCTAssertEqual(values(IndicatorAbout(off, baseline: [shipped], pack: nil))["State"], "Unchanged",
                       "Off isn't a change to the indicator")
        XCTAssertEqual(values(IndicatorAbout(off, baseline: [shipped], pack: nil))["Source"], "Mac Monitor")
    }

    /// One added on this Mac says so, with no revision or state, and lists every event type its rule names. A
    /// sequence lists its steps' types, and a rule that names none says so.
    func testAnIndicatorAddedHereAndItsEventTypes() {
        let own = ownIndicator("Mine", "(event.close != nil AND event.close.modified == YES) OR event.rename != nil")
        let about = IndicatorAbout(own, baseline: Indicator.defaults, pack: nil)
        XCTAssertEqual(about.rows.map(\.name), ["ID", "Source", "Runs on"])
        XCTAssertEqual(values(about)["Source"], "Added on this Mac")
        XCTAssertEqual(about.summary, "Added on this Mac")
        XCTAssertEqual(values(about)["Runs on"], "close, rename")
        let steps = [IndicatorSequence.Step(name: "ran", predicate: "event.exec != nil"),
                     IndicatorSequence.Step(name: "opened", predicate: "event.open != nil")]
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: steps))
        XCTAssertEqual(values(IndicatorAbout(sequence, baseline: [], pack: nil))["Runs on"], "exec, open")
        let untyped = ownIndicator("Untyped", #"process.executable.name == "curl""#)
        XCTAssertEqual(values(IndicatorAbout(untyped, baseline: [], pack: nil))["Runs on"], "No event type")
    }

    /// Every indicator the build ships has something to say: its pack and revision, and at least one event type.
    func testEveryShippedIndicatorIsDescribed() {
        let status = IndicatorBaseline.linked.status(linked: IndicatorBaseline.linked.sequence)
        for indicator in Indicator.defaults {
            let facts = values(IndicatorAbout(indicator, baseline: Indicator.defaults, pack: status))
            XCTAssertEqual(facts["State"], "Unchanged", indicator.name)
            XCTAssertEqual(facts["Revision"], indicator.revision.map(String.init), indicator.name)
            XCTAssertNotEqual(facts["Runs on"], "No event type", indicator.name)
            XCTAssertEqual(facts["Source"], "Mac Monitor (Pack \(status.sequence))", indicator.name)
        }
    }
}
