//
//  ReleaseVersionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Release versions
/// Pins how a pack's version of Mac Monitor reads and compares, how an indicator that needs a newer one is kept but
/// not run, and that this build's engine version follows the project's.
final class ReleaseVersionTests: XCTestCase {
    /// Three dot-separated numbers read, and anything else doesn't.
    func testParsing() {
        XCTAssertEqual(ReleaseVersion("3.2.0"), ReleaseVersion(3, 2, 0))
        XCTAssertEqual(ReleaseVersion("10.0.12"), ReleaseVersion(10, 0, 12))
        for text in ["", "3.2", "3.2.0.1", "v3.2.0", "3.2.0-beta", "3..0", "3.2.x", " 3.2.0", "+3.2.0", "3.2.٣"] {
            XCTAssertNil(ReleaseVersion(text), text)
        }
        XCTAssertEqual(ReleaseVersion(3, 2, 0).description, "3.2.0")
    }

    /// Versions compare by number, not as text.
    func testOrdering() {
        XCTAssertLessThan(ReleaseVersion(3, 9, 9), ReleaseVersion(3, 10, 0))
        XCTAssertLessThan(ReleaseVersion(3, 2, 0), ReleaseVersion(3, 2, 1))
        XCTAssertLessThan(ReleaseVersion(2, 99, 99), ReleaseVersion(3, 0, 0))
    }

    /// A version is a string in JSON, and one that isn't three numbers doesn't decode.
    func testCoding() throws {
        let data = try JSONEncoder().encode([ReleaseVersion(3, 2, 0)])
        XCTAssertEqual(String(decoding: data, as: UTF8.self), #"["3.2.0"]"#)
        XCTAssertEqual(try JSONDecoder().decode([ReleaseVersion].self, from: data), [ReleaseVersion(3, 2, 0)])
        XCTAssertThrowsError(try JSONDecoder().decode([ReleaseVersion].self, from: Data(#"["3.2"]"#.utf8)))
    }

    /// An indicator that needs a newer Mac Monitor than this build is kept, says so, and isn't run: it has no
    /// predicate to match events with, and the Security Extension's set lists it as a problem.
    func testNewerIndicatorIsKeptButNotRun() {
        let later = ReleaseVersion(Indicator.engineVersion.major, Indicator.engineVersion.minor + 1, 0)
        var indicator = Indicator(name: "Later", description: "", symbol: "star", color: .red,
                                  predicate: "event.exec != nil")
        indicator.minEngine = later
        XCTAssertFalse(indicator.isSupported)
        XCTAssertNil(indicator.eventPredicate)
        XCTAssertEqual(indicator.problem, "It needs Mac Monitor \(later) or later.")
        XCTAssertEqual(indicator.sensorProblem, indicator.problem)
        let compiled = CompiledIndicators([indicator], defaults: [:])
        XCTAssertEqual(compiled.problems.map(\.id), [indicator.id])
        indicator.minEngine = Indicator.engineVersion
        XCTAssertTrue(indicator.isSupported)
        XCTAssertNil(indicator.problem)
    }

    /// This build's engine version is the project's version, or the next while it isn't released: the same major
    /// version, and never older. So a release that forgets to bump it fails here.
    func testEngineVersionFollowsTheProject() throws {
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("ProjectSutro.xcodeproj/project.pbxproj")
        let text = try String(contentsOf: project, encoding: .utf8)
        let versions = Set(text.matches(of: #/MARKETING_VERSION = ([0-9.]+);/#).map { String($0.output.1) })
        XCTAssertFalse(versions.isEmpty)
        for version in versions {
            let marketing = try XCTUnwrap(ReleaseVersion(version), version)
            XCTAssertEqual(Indicator.engineVersion.major, marketing.major, version)
            XCTAssertGreaterThanOrEqual(Indicator.engineVersion, marketing, version)
        }
    }
}
