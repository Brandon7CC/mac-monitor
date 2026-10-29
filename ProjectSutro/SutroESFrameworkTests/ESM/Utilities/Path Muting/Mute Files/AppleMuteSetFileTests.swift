//
//  AppleMuteSetFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/29/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Apple's mute sets in the repository
/// Pins the Apple mute sets committed in `Mute sets/`, as Export Apple Mute Set… writes them: one `ESMutedPath` per
/// line, each event named as `ESTypes.h` names it. An export from a Mac Monitor that didn't know an event type would
/// say `ES_EVENT_TYPE_LAST` and fails here.
final class AppleMuteSetFileTests: XCTestCase {
    /// The repository's `Mute sets` folder.
    private static var muteSetsURL: URL { repositoryURL.appendingPathComponent("Mute sets") }

    /// Every committed Apple mute set: `es_default_mute_set_<macOS version>.json`.
    ///
    /// - Throws: If the folder can't be listed.
    /// - Returns: The files, sorted by name.
    private func muteSetFiles() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: Self.muteSetsURL, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("es_default_mute_set_") && $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    /// A macOS 27 set is there, along with the earlier ones.
    func testTheSetsAreThere() throws {
        let names = try muteSetFiles().map(\.lastPathComponent)
        XCTAssertTrue(names.contains { $0.hasPrefix("es_default_mute_set_27") }, "\(names)")
        XCTAssertGreaterThanOrEqual(names.count, 3)
    }

    /// Every line is a mute whose events are all named, known to Mac Monitor, and counted.
    func testEveryEventIsNamed() throws {
        for file in try muteSetFiles() {
            let name = file.lastPathComponent
            let lines = try String(contentsOf: file, encoding: .utf8).split(separator: "\n")
            XCTAssertFalse(lines.isEmpty, name)
            for (index, line) in lines.enumerated() {
                let mute = try JSONDecoder().decode(ESMutedPath.self, from: Data(line.utf8))
                let at = "\(name):\(index + 1) \(mute.path)"
                XCTAssertTrue(mute.path.hasPrefix("/"), at)
                XCTAssertTrue(mute.type.hasPrefix("ES_MUTE_PATH_TYPE_"), at)
                XCTAssertEqual(mute.eventCount, mute.events.count, at)
                for event in mute.events {
                    XCTAssertNotEqual(eventStringToType(from: event), ES_EVENT_TYPE_LAST, "\(at): \(event)")
                }
            }
        }
    }
}
