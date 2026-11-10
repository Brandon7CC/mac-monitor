//
//  DestinationSpellingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/10/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A new path's target path
/// Pins that a create's or a rename's target path in the spelling 3.0 gave it (`/dir\/name`), which a 3.0 Security
/// Extension and an export made before 3.1 still send, is written again as 3.1 writes it, so indicators and filters
/// on `target_path` read the same path either way.
final class DestinationSpellingTests: XCTestCase {
    /// Every synthetic create and rename to a new path, given 3.0's spelling, comes back with 3.1's target path and
    /// context once it's received. One already in 3.1's spelling, and an event of another type, are left as they are.
    func testAnOldSpellingIsWrittenAgain() throws {
        var respelled = 0
        for message in try SyntheticCorpus.records().map(\.message) {
            let destination: FileDestination
            switch message.event {
            case .create(let event): destination = event.destination
            case .rename(let event): destination = event.destination
            default:
                var other = message
                other.respellDestination()
                XCTAssertEqual(other.target_path, message.target_path)
                continue
            }
            var received = message
            if case .new_path(let path) = destination {
                received.target_path = "\(path.dir.path)\\/\(path.filename)"
                received.context = "stale"
                respelled += 1
            }
            received.completeReceived { _, _ in nil }
            XCTAssertEqual(received.target_path, message.target_path)
            XCTAssertEqual(received.context, message.context)
        }
        XCTAssertGreaterThan(respelled, 0)
    }
}
