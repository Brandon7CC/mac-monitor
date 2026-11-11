//
//  LaunchItemCaptureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - A launch item's bundles at capture
/// Pins what ``LaunchItem/init(from:)`` reads from disk for each item type: an app's or login item's bundle and
/// Info.plist, a login item's path relative to its app, an agent's app bundle and launchd plist (binary converted to
/// XML), plists reached through a symbolic link (never read), a user item that isn't a bundle, and an item that's
/// gone. Opening a trace reads nothing
/// (``LaunchItem/enrich()``).
final class LaunchItemCaptureTests: XCTestCase {
    /// An app item, as `System Events` adds one for "make login item": the app's URL, with no app.
    func testAppItemReadsItsBundle() throws {
        let path = try makeBundle("Example.app")
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_APP, url: fileURL(path)))
        XCTAssertEqual(item.item_path, path)
        let bundle = try XCTUnwrap(item.bundle)
        XCTAssertEqual(bundle.path, path)
        XCTAssertEqual(bundle.identifier, "com.example.helper")
        XCTAssertNil(item.app_bundle)
        XCTAssertEqual(item.plist_contents, try String(contentsOfFile: path + "/Contents/Info.plist", encoding: .utf8))
    }

    /// An `SMAppService` login item's path is relative to its app: both bundles are read.
    func testLoginItemRelativeToItsApp() throws {
        let app = try makeBundle("Parent.app", info: ["CFBundleIdentifier": "com.example.parent"])
        try makeBundle("Contents/Library/LoginItems/Helper.app", in: URL(fileURLWithPath: app), format: .binary)
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_LOGIN_ITEM,
                                                  url: "Contents/Library/LoginItems/Helper.app",
                                                  appURL: fileURL(app)))
        XCTAssertEqual(item.bundle?.path, app + "/Contents/Library/LoginItems/Helper.app")
        XCTAssertEqual(item.bundle?.identifier, "com.example.helper")
        XCTAssertEqual(item.app_bundle?.path, app)
        XCTAssertEqual(item.app_bundle?.identifier, "com.example.parent")
        XCTAssertTrue(item.plist_contents?.hasPrefix("<?xml") ?? false, "The helper's binary Info.plist, as XML")
    }

    /// A login item named by its full URL is read where it is.
    func testLoginItemWithAbsoluteURL() throws {
        let app = try makeBundle("Parent.app")
        let helper = try makeBundle("Contents/Library/LoginItems/Helper.app", in: URL(fileURLWithPath: app))
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_LOGIN_ITEM, url: fileURL(helper),
                                                  appURL: fileURL(app)))
        XCTAssertEqual(item.bundle?.path, helper)
        XCTAssertEqual(item.app_bundle?.path, app)
    }

    /// An agent's plist, stored in binary, is kept as XML. Its app's bundle is read, and the agent has none of its own.
    func testAgentGetsItsAppBundleAndXMLPlist() throws {
        let app = try makeBundle("Parent.app")
        let agents = URL(fileURLWithPath: app).appendingPathComponent("Contents/Library/LaunchAgents")
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        let plist: [String: Any] = ["Label": "com.example.agent", "BundleProgram": "Contents/MacOS/Helper"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
            .write(to: agents.appendingPathComponent("com.example.agent.plist"))
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_AGENT,
                                                  url: "Contents/Library/LaunchAgents/com.example.agent.plist",
                                                  appURL: fileURL(app)))
        XCTAssertNil(item.bundle)
        XCTAssertEqual(item.app_bundle?.path, app)
        let text = try XCTUnwrap(item.plist_contents)
        XCTAssertTrue(text.hasPrefix("<?xml"), text)
        XCTAssertTrue(text.contains("<string>com.example.agent</string>"), text)
    }

    /// A legacy daemon's binary plist, at an absolute path, is kept as XML. An XML one is kept as it's written.
    func testLegacyDaemonPlists() throws {
        let directory = try makeTemporaryDirectory()
        let binary = directory.appendingPathComponent("com.example.binary.plist")
        try PropertyListSerialization.data(fromPropertyList: ["Label": "com.example.binary"], format: .binary,
                                           options: 0).write(to: binary)
        let xml = directory.appendingPathComponent("com.example.xml.plist")
        let xmlData = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.example.xml"], format: .xml,
                                                         options: 0)
        try xmlData.write(to: xml)

        let converted = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_DAEMON, url: fileURL(binary.path),
                                                       legacy: true))
        XCTAssertTrue(converted.plist_contents?.contains("<string>com.example.binary</string>") ?? false)
        let kept = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_DAEMON, url: fileURL(xml.path), legacy: true))
        XCTAssertEqual(kept.plist_contents, String(decoding: xmlData, as: UTF8.self))
        XCTAssertNil(kept.bundle)
        XCTAssertNil(kept.app_bundle)
    }

    /// An agent's plist reached through a symbolic link below its app, or a legacy plist that's a link, isn't read: a
    /// local user could otherwise have root read, and Mac Monitor show, a plist that user can't read.
    func testLinkedPlistsArentRead() throws {
        let secrets = try makeTemporaryDirectory()
        let secret = secrets.appendingPathComponent("com.example.agent.plist")
        try PropertyListSerialization.data(fromPropertyList: ["Label": "com.example.secret"], format: .binary,
                                           options: 0).write(to: secret)
        let app = try makeBundle("Parent.app")
        let library = app + "/Contents/Library"
        try FileManager.default.createDirectory(atPath: library, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: library + "/LaunchAgents", withDestinationPath: secrets.path)
        let agent = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_AGENT,
                                                   url: "Contents/Library/LaunchAgents/com.example.agent.plist",
                                                   appURL: fileURL(app)))
        XCTAssertNil(agent.plist_contents)

        let link = try makeTemporaryDirectory().appendingPathComponent("com.example.link.plist")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: secret)
        let legacy = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_DAEMON, url: fileURL(link.path), legacy: true))
        XCTAssertNil(legacy.plist_contents)
        XCTAssertNotNil(ProcessHelpers.getPropertyListContents(secret.lastPathComponent, in: secrets.path),
                        "The plist itself, where it is")
    }

    /// A binary plist longer than the limit can't be converted, so it has no text.
    func testOversizedBinaryPlistHasNoText() {
        var data = Data("bplist00".utf8)
        data.append(Data(count: ProcessHelpers.fileContentsLimit))
        XCTAssertNil(ProcessHelpers.propertyListText(of: data))
        XCTAssertNil(ProcessHelpers.propertyListText(of: Data("bplist00 garbage".utf8)))
    }

    /// A user item naming a file that isn't a bundle has no bundle and no plist.
    func testUserItemThatIsntABundle() throws {
        let file = try temporaryFile(containing: "#!/bin/sh\n", named: "tool.sh")
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_USER_ITEM, url: fileURL(file.path)))
        XCTAssertNil(item.bundle)
        XCTAssertNil(item.plist_contents)
    }

    /// An item removed with its bundle has nothing to read, and its app may be gone too.
    func testRemovedItemIsGone() throws {
        let gone = try makeTemporaryDirectory().appendingPathComponent("Gone.app").path
        let item = LaunchItem(from: rawLaunchItem(ES_BTM_ITEM_TYPE_LOGIN_ITEM, url: "Contents/Library/LoginItems/X.app",
                                                  appURL: "file://\(gone)/"))
        XCTAssertNil(item.bundle)
        XCTAssertNil(item.app_bundle)
        XCTAssertNil(item.plist_contents)
    }

    /// The whole event, as the Security Extension records it: the bundle's age is dated against the message.
    func testCapturedAddEventDatesItsBundle() throws {
        let path = try makeBundle("Example.app")
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)
        var info = stat()
        XCTAssertEqual(stat(path, &info), 0)
        /// The message is 2.5 s after the bundle's birth.
        fixture.message.pointee.time = timespec(tv_sec: info.st_birthtimespec.tv_sec + 2,
                                                tv_nsec: info.st_birthtimespec.tv_nsec + 500_000_000)
        let event = fixture.allocate(es_event_btm_launch_item_add_t.self)
        event.pointee.item = fixture.pointer(rawLaunchItem(ES_BTM_ITEM_TYPE_APP, url: fileURL(path)))
        fixture.message.pointee.event.btm_launch_item_add = event
        let message = Message(from: fixture.raw)
        guard case .btm_launch_item_add(let add) = message.event else { return XCTFail("Not an add") }
        XCTAssertEqual(add.item.bundle?.age_ms, 2_500)
    }

    /// A launch item decoded from a trace and enriched reads nothing from this Mac, even when its path is a bundle.
    func testEnrichReadsNothing() throws {
        let path = try makeBundle("Example.app")
        let json = #"{"item_type": 1, "item_url": "\#(fileURL(path))", "legacy": false, "managed": false, "uid": 501}"#
        var item = try TraceDecoder(try JSONSerialization.jsonObject(with: Data(json.utf8)) as AnyObject,
                                    enriching: true).decode(LaunchItem.self)
        item.enrich()
        XCTAssertEqual(item.item_path, path)
        XCTAssertNil(item.bundle)
        XCTAssertNil(item.app_bundle)
        XCTAssertNil(item.plist_contents)
    }
}
