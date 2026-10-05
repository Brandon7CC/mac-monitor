//
//  MountDispositionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mount disposition
/// Pins an opened trace's mount `disposition`: Endpoint Security's from message version 8 (`ESMessage.h`), so
/// eslogger writes none before it. The Security Extension records those mounts as unknown
/// (`CaptureCrashGuardTests.testMountDispositionBeforeVersion8()`), and an opened trace now reads them the same way
/// rather than as 0, an external device.
final class MountDispositionTests: XCTestCase {
    /// A mounted disk image's file system, as eslogger writes it.
    private static let statfs: [String: Any] = [
        "f_bsize": 4_096, "f_iosize": 1_048_576, "f_blocks": 2_048, "f_bfree": 1_024, "f_bavail": 1_024,
        "f_files": 4_096, "f_ffree": 4_000, "f_fsid": [16_777_240, 26], "f_owner": 501, "f_type": 26,
        "f_flags": 276_828_185, "f_fssubtype": 0, "f_flags_ext": 0, "f_fstypename": "apfs",
        "f_mntonname": "/Volumes/Example", "f_mntfromname": "/dev/disk5s1",
    ]
    
    /// The export of an eslogger mount record.
    ///
    /// - Parameters:
    ///   - version: The message's version.
    ///   - disposition: The record's disposition, or `nil` to leave the key out.
    /// - Returns: The exported mount event.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no mount event.
    private func exportedMount(version: Int, disposition: Int?) throws -> [String: Any] {
        var event: [String: Any] = ["statfs": Self.statfs]
        event["disposition"] = disposition
        let record = try esloggerRecord("mount", type: 22, event, version: version)
        return try self.event("mount", in: try export(try importRecord(record)))
    }
    
    /// Before message version 8 there's no disposition: it's unknown.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no mount event.
    func testImportedBeforeVersion8() throws {
        let mount = try exportedMount(version: 7, disposition: nil)
        XCTAssertEqual(mount["disposition"] as? Int, Int(ES_MOUNT_DISPOSITION_UNKNOWN.rawValue))
        XCTAssertEqual(mount["disposition_string"] as? String, "ES_MOUNT_DISPOSITION_UNKNOWN")
        XCTAssertEqual((mount["statfs"] as? [String: Any])?["f_mntonname"] as? String, "/Volumes/Example")
    }
    
    /// From message version 8 the trace's disposition is kept, an external device (0) included.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no mount event.
    func testImportedFromVersion8() throws {
        let mount = try exportedMount(version: 8, disposition: Int(ES_MOUNT_DISPOSITION_EXTERNAL.rawValue))
        XCTAssertEqual(mount["disposition"] as? Int, Int(ES_MOUNT_DISPOSITION_EXTERNAL.rawValue))
        XCTAssertEqual(mount["disposition_string"] as? String, "ES_MOUNT_DISPOSITION_EXTERNAL")
    }
    
    /// The Security Extension's JSON reaches Mac Monitor with the disposition it recorded.
    ///
    /// - Throws: The error encoding or decoding the message.
    func testWireRoundTrip() throws {
        let fixture = rawMessage(version: 8, type: ES_EVENT_TYPE_NOTIFY_MOUNT)
        fixture.message.pointee.event.mount.statfs = fixture.allocate(Darwin.statfs.self)
        fixture.message.pointee.event.mount.disposition = ES_MOUNT_DISPOSITION_EXTERNAL
        let sent = try JSONEncoder().encode(Message(from: fixture.raw))
        let mount = try XCTUnwrap(try JSONDecoder().decode(Message.self, from: sent).event.mount)
        XCTAssertEqual(mount.disposition, Int16(ES_MOUNT_DISPOSITION_EXTERNAL.rawValue))
        XCTAssertEqual(mount.disposition_string, "ES_MOUNT_DISPOSITION_EXTERNAL")
    }
}
