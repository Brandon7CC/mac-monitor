//
//  GatekeeperFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Gatekeeper override file
/// Pins how a `gatekeeper_user_override` event's `file` union is read and exported: eslogger writes either arm under
/// `file`, the path arm as the path itself (`null` when it's `NULL`) and the file arm as an `es_file_t` object, chosen
/// by `file_type`. Mac Monitor's own `file_path` is kept beside it.
final class GatekeeperFileTests: XCTestCase {
    /// The overridden app.
    private static let path = "/Applications/Example.app"
    
    /// An eslogger `gatekeeper_user_override` record, read and exported.
    ///
    /// - Parameter event: The event's object.
    /// - Returns: The export, and the exported event's object.
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    private func exported(_ event: [String: Any]) throws -> (export: [String: Any], event: [String: Any]) {
        let export = try export(try importRecord(try esloggerRecord("gatekeeper_user_override", type: 146, event)))
        return (export, try self.event("gatekeeper_user_override", in: export))
    }
    
    /// eslogger's path arm is read as the path and exported under `file`, as eslogger writes it.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testPathArm() throws {
        let (export, gatekeeper) = try exported(["file_type": 0, "file": Self.path, "sha256": NSNull(),
                                                 "signing_info": NSNull()])
        XCTAssertEqual(gatekeeper["file"] as? String, Self.path)
        XCTAssertEqual(gatekeeper["file_path"] as? String, Self.path)
        XCTAssertEqual(gatekeeper["file_type_string"] as? String, "ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH")
        XCTAssertEqual(gatekeeper["sha256"] as? String, "NULL")
        XCTAssertTrue(gatekeeper["signing_info"] is NSNull)
        XCTAssertEqual(export["target_path"] as? String, Self.path)
    }
    
    /// The file arm is an `es_file_t` object under `file`, with no `file_path`.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testFileArm() throws {
        let executable = Self.path + "/Contents/MacOS/Example"
        let (_, gatekeeper) = try exported(["file_type": 1, "sha256": NSNull(), "signing_info": NSNull(),
                                            "file": ["path": executable, "path_truncated": false, "stat": [:]]])
        XCTAssertEqual((gatekeeper["file"] as? [String: Any])?["path"] as? String, executable)
        XCTAssertNil(gatekeeper["file_path"])
    }
    
    /// A path arm whose path is `NULL` is `null` under `file`, as eslogger writes it.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testNullPathArm() throws {
        let (_, gatekeeper) = try exported(["file_type": 0, "file": NSNull(), "sha256": NSNull(),
                                            "signing_info": NSNull()])
        XCTAssertTrue(gatekeeper["file"] is NSNull)
        XCTAssertNil(gatekeeper["file_path"])
    }
    
    /// A `file_type` that names neither arm exports no `file`: eslogger has no value to match.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testUnknownFileType() throws {
        let (_, gatekeeper) = try exported(["file_type": 7, "file": [:], "sha256": NSNull(), "signing_info": NSNull()])
        XCTAssertNil(gatekeeper["file"])
        XCTAssertNil(gatekeeper["file_path"])
    }
    
    /// Mac Monitor 2.1 wrote the path arm as `file_path` beside the union: it's read and exported under `file` too.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testMacMonitor21PathArm() throws {
        let record = try legacyRecord("gatekeeper_user_override", type: ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, [
            "file_type": 0, "file_path": Self.path, "sha256": "NULL",
            "file_type_string": "ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH",
        ])
        let gatekeeper = try event("gatekeeper_user_override", in: try export(try importRecord(record)))
        XCTAssertEqual(gatekeeper["file"] as? String, Self.path)
        XCTAssertEqual(gatekeeper["file_path"] as? String, Self.path)
    }
    
    /// The Security Extension's path arm exports the same way.
    ///
    /// - Throws: An `XCTest` failure if the export has no Gatekeeper event.
    func testCapturedPathArm() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE)
        let override = fixture.allocate(es_event_gatekeeper_user_override_t.self)
        override.pointee.file_type = ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH
        override.pointee.file.file_path = fixture.token(Self.path)
        fixture.message.pointee.event.gatekeeper_user_override = override
        let gatekeeper = try event("gatekeeper_user_override", in: try export(Message(from: fixture.raw)))
        XCTAssertEqual(gatekeeper["file"] as? String, Self.path)
        XCTAssertEqual(gatekeeper["file_path"] as? String, Self.path)
    }
}
