//
//  XProtectRuleStatusTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What Settings says of the rules
/// Pins the words Settings > XProtect Rules puts after the version and the count, and how the status travels.
final class XProtectRuleStatusTests: XCTestCase {
    /// Each state's words, with the loaded version only when it isn't the one listed, and loaded rules with a rule
    /// file that didn't load said to be partly loaded.
    func testWhatSettingsSays() {
        let said = [XProtectRuleStatus.State.off, .waiting, .unloaded, .loaded, .failed].map {
            XProtectRuleStatus(state: $0, version: "5377").summary(listing: "5377")
        }
        XCTAssertEqual(said, ["scanning is off", "loads once Close or Exec events are captured",
                              "loads when a file is scanned", "compiled and loaded", "didn't load"])
        XCTAssertEqual(XProtectRuleStatus(state: .loaded, version: "5376").summary(listing: "5377"),
                       "XProtect 5376 compiled and loaded")
        XCTAssertEqual(XProtectRuleStatus(state: .loaded, version: "5377", problems: ["XPScripts.yr didn't compile."])
            .summary(listing: "5377"), "partly loaded")
    }

    /// A status reads back as it was sent, and a state a later Security Extension might send reads as no answer.
    func testTheStatusTravels() throws {
        let status = XProtectRuleStatus(state: .failed, problems: ["XProtect.yara didn't compile."])
        XCTAssertEqual(try JSONDecoder().decode(XProtectRuleStatus.self, from: status.encoded), status)
        let later = Data(#"{"state":"compiling","problems":[]}"#.utf8)
        XCTAssertNil(try? JSONDecoder().decode(XProtectRuleStatus.self, from: later))
    }
}
