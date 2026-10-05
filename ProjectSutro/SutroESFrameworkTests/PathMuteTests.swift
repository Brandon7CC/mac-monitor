//
//  PathMuteTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Path mutes
/// Pins path mutes as values: Mac Monitor's default set flattened to one mute per path.
final class PathMuteTests: XCTestCase {
    /// Every path of every default rule becomes one mute: event-specific ones first, each scoped to its one event,
    /// then global ones, scoped to none.
    func testDefaultMuteSetFlattensEveryRule() {
        let muteSet = MuteSet.default(home: ConsoleUser.tester.home)
        let mutes = muteSet.pathMutes
        let scopedCount = muteSet.eventSpecificRules.map { $0.paths.count }.reduce(0, +)
        let globalCount = muteSet.globalRules.map { $0.paths.count }.reduce(0, +)
        XCTAssertEqual(mutes.count, scopedCount + globalCount)
        XCTAssertGreaterThan(scopedCount, 0)
        XCTAssertGreaterThan(globalCount, 0)
        
        let scoped = Array(mutes.prefix(scopedCount))
        let expected = muteSet.eventSpecificRules.flatMap { rule in rule.paths.map { (rule, $0) } }
        for (mute, (rule, path)) in zip(scoped, expected) {
            XCTAssertEqual(mute, PathMute(path: path, type: rule.muteType, events: [rule.eventType]))
        }
        for mute in mutes.suffix(globalCount) {
            XCTAssertTrue(mute.events.isEmpty, mute.path)
        }
        XCTAssertEqual(mutes.last, PathMute(path: muteSet.globalRules.last?.paths.last ?? "",
                                            type: muteSet.globalRules.last?.pathType ?? ES_MUTE_PATH_TYPE_PREFIX))
    }
    
}
