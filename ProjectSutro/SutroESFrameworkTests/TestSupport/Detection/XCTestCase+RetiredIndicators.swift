//
//  XCTestCase+RetiredIndicators.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A shipped indicator this build dropped
extension XCTestCase {
    /// osascript's identity, which 3.1.0 stopped shipping and nothing ships again.
    static let osascriptID = Indicator.uuid(12)

    /// osascript as the build before this one shipped it: 3.0.0's rule, with the tactic, technique and severity it
    /// had when it was dropped. It stands for any default a later build drops.
    ///
    /// - Returns: The indicator.
    func droppedOsascript() throws -> Indicator {
        Indicator(id: Self.osascriptID, name: "osascript",
                  description: "osascript ran AppleScript or JXA, which stealers use for fake password prompts and "
                    + "to drive other apps.",
                  symbol: "applescript", color: .indigo,
                  predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "#
                    + #"event.exec.target.executable.name == "osascript""#,
                  tactic: .execution, technique: "T1059.002", severity: .low)
    }

    /// osascript with its rule changed to match osacompile too, so the user's own once this build no longer ships it.
    /// The Security Extension can run it.
    ///
    /// - Returns: The indicator, on.
    func editedOsascript() throws -> Indicator {
        var edited = try droppedOsascript()
        edited.predicate = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.target.executable.name "#
            + #"IN {"osascript", "osacompile"}"#
        return edited
    }

    /// The indicators the build before this one shipped: this build's, with osascript after Ran a script, where it
    /// was.
    ///
    /// - Returns: Them, in order.
    /// - Throws: A failure when Ran a script or osascript can't be found.
    func defaultsWithOsascript() throws -> [Indicator] {
        var earlier = Indicator.defaults
        let script = try XCTUnwrap(earlier.firstIndex { $0.name == "Ran a script" }, "No Ran a script")
        earlier.insert(try droppedOsascript(), at: script + 1)
        return earlier
    }

    /// A saved set as the build before this one wrote it, with osascript as given in its place.
    ///
    /// - Parameter osascript: osascript as the Mac had it: switched, given a severity or edited.
    /// - Returns: The set's JSON object: an indicator file's `saved`, or Mac Monitor 3.0's `findings` default.
    /// - Throws: A failure when the set can't be made or encoded.
    func savedWithOsascript(_ osascript: Indicator) throws -> [String: Any] {
        let earlier = try defaultsWithOsascript()
        let indicators = earlier.map { $0.id == Self.osascriptID ? osascript : $0 }
        return try XCTUnwrap(SavedIndicators(indicators, defaults: earlier).encodedObject())
    }

    /// The saved entry that names osascript.
    ///
    /// - Parameter saved: A saved set's JSON object.
    /// - Returns: The entry: a reference, or osascript in full.
    /// - Throws: A failure when no entry names it.
    func osascriptEntry(in saved: [String: Any]) throws -> [String: Any] {
        let entries = try XCTUnwrap(saved["entries"] as? [[String: Any]])
        return try XCTUnwrap(entries.first { entry in
            [entry["default"], entry["id"]].contains { ($0 as? String) == Self.osascriptID.uuidString }
        }, "No entry names osascript")
    }
}
