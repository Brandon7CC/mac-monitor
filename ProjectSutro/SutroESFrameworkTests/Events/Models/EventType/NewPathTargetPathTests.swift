//
//  NewPathTargetPathTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - New paths as target paths
/// Pins that a create or rename whose destination is a new file has the file's path as its `target_path`: its
/// directory and name joined by one "/". Before 3.1.0 they were joined with "\/", so searches, filters and indicators
/// on the path saw a path no file has.
final class NewPathTargetPathTests: XCTestCase {
    /// A create of a new file.
    func testCreateOfANewFile() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.create("Notes.txt", in: "/Users/Shared")
        XCTAssertEqual(Message(from: fixture.raw).target_path, "/Users/Shared/Notes.txt")
    }

    /// A directory that already ends in "/" gets no second one.
    func testDirectoryEndingInASlash() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.create("Notes.txt", in: "/")
        XCTAssertEqual(Message(from: fixture.raw).target_path, "/Notes.txt")
    }

    /// A rename into a new file, as a safe save renames its temporary file over the one it saves.
    func testRenameIntoANewFile() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_RENAME)
        fixture.message.pointee.event.rename.source = fixture.file("/Users/Shared/saved.plist.tmp")
        fixture.message.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        fixture.message.pointee.event.rename.destination.new_path.dir = fixture.file("/Users/Shared")
        fixture.message.pointee.event.rename.destination.new_path.filename = fixture.token("saved.plist")
        let message = Message(from: fixture.raw)
        XCTAssertEqual(message.target_path, "/Users/Shared/saved.plist")
        XCTAssertEqual(message.context, "saved.plist.tmp → saved.plist")
    }
}
