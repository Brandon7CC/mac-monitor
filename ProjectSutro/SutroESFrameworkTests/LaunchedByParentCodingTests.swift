//
//  LaunchedByParentCodingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The launched-by parent's JSON
/// Pins the launched-by parent's JSON: one shape with every key, tokens as eslogger writes them, and a reader that
/// never costs the event holding it.
final class LaunchedByParentCodingTests: XCTestCase {
    /// A shell's child's answer.
    private let shellChild = LaunchedByParent(source: .unixParent, audit_token: .fixture(pid: 401, pidversion: 4010),
                                              path: "/bin/zsh", resolved_by: .securityExtension)
    /// An answer that names no process: an app `open` launched.
    private let unnamed = LaunchedByParent(source: .launchServices, audit_token: nil, path: nil,
                                           launchd_job: .init(label: "application.com.example.App.1.2.0"),
                                           resolved_by: .app)
    
    /// A value's JSON object, as `JSONEncoder` writes it.
    ///
    /// - Parameter value: The value.
    /// - Returns: The object.
    /// - Throws: The encoder's error, or an `XCTest` failure if it isn't an object.
    private func object(_ value: some Encodable) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
    }
    
    /// Every key is written, `null` when unknown, and a token has eslogger's eight keys and no `id`.
    ///
    /// - Throws: The encoder's error.
    func testEveryKeyIsWritten() throws {
        let keys: Set = ["source", "audit_token", "pid", "path", "launchd_job", "resolved_by"]
        let named = try object(shellChild)
        XCTAssertEqual(Set(named.keys), keys)
        XCTAssertTrue(named["launchd_job"] is NSNull)
        XCTAssertEqual(named["pid"] as? Int, 401, "the token's pid")
        let token = try XCTUnwrap(named["audit_token"] as? [String: Any])
        XCTAssertEqual(Set(token.keys), ["asid", "auid", "egid", "euid", "pid", "pidversion", "rgid", "ruid"])
        
        let none = try object(unnamed)
        XCTAssertEqual(Set(none.keys), keys)
        for key in ["audit_token", "pid", "path"] { XCTAssertTrue(none[key] is NSNull, key) }
        let job = try XCTUnwrap(none["launchd_job"] as? [String: Any])
        XCTAssertEqual(job["label"] as? String, "application.com.example.App.1.2.0")
    }
    
    /// What's written reads back equal, and so does a token with Mac Monitor's `id`.
    ///
    /// - Throws: The encoder's or decoder's error.
    func testRoundTrip() throws {
        for value in [shellChild, unnamed] {
            XCTAssertEqual(try JSONDecoder().decode(LaunchedByParent.self, from: JSONEncoder().encode(value)), value)
        }
        var object = try object(shellChild)
        var token = try XCTUnwrap(object["audit_token"] as? [String: Any])
        token["id"] = UUID().uuidString
        object["audit_token"] = token
        let withID = try JSONSerialization.data(withJSONObject: object)
        XCTAssertEqual(try JSONDecoder().decode(LaunchedByParent.self, from: withID), shellChild)
    }
    
    /// An export's sorted keys give one fixed text, and an answer stays small.
    ///
    /// - Throws: The encoder's error.
    func testSortedShape() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let text = String(decoding: try encoder.encode(shellChild), as: UTF8.self)
        XCTAssertEqual(text, #"{"audit_token":{"asid":100000,"auid":4294967295,"egid":0,"euid":0,"pid":401,"#
                       + #""pidversion":4010,"rgid":0,"ruid":0},"launchd_job":null,"path":"/bin/zsh","pid":401,"#
                       + #""resolved_by":"security_extension","source":"unix_parent"}"#)
        XCTAssertLessThanOrEqual(text.utf8.count, 300)
    }
    
    /// Read on its own, a launched-by parent with an unknown source or resolver, or none, is an error.
    func testDecodingIsStrict() {
        for json in [#"{"source":"elsewhere","resolved_by":"app"}"#, #"{"source":"unix_parent","resolved_by":"x"}"#,
                     #"{"resolved_by":"app"}"#, #"{"source":"unix_parent","resolved_by":"app","pid":"one"}"#] {
            XCTAssertThrowsError(try JSONDecoder().decode(LaunchedByParent.self, from: Data(json.utf8)), json)
        }
    }
    
    /// Read as a member, one that can't be read is no launched-by parent, and the object holding it still reads.
    ///
    /// - Throws: The decoder's error for the object holding it.
    func testReadingAsMemberIsLenient() throws {
        /// An object with a launched-by parent, decoded the way an exec or fork event decodes its own.
        struct Holder: Decodable {
            let pid: Int
            let launched_by_parent: LaunchedByParent?
        }
        let valid = String(decoding: try JSONEncoder().encode(shellChild), as: UTF8.self)
        let json = Data(#"{"pid":1,"launched_by_parent":\#(valid)}"#.utf8)
        XCTAssertEqual(try JSONDecoder().decode(Holder.self, from: json).launched_by_parent, shellChild)
        for member in [#""launched_by_parent":{"source":"elsewhere","resolved_by":"app"}"#,
                       #""launched_by_parent":"unix_parent""#, #""launched_by_parent":[]"#,
                       #""launched_by_parent":null"#, #""pid_too":2"#] {
            let holder = try JSONDecoder().decode(Holder.self, from: Data(#"{"pid":1,\#(member)}"#.utf8))
            XCTAssertNil(holder.launched_by_parent, member)
            XCTAssertEqual(holder.pid, 1, member)
        }
    }
    
    /// A token's identity is its pid and pid version, whatever its `id`.
    func testSameProcess() {
        let token = AuditToken(from: RawMessageFixture.auditToken(pid: 401, pidversion: 4010))
        XCTAssertTrue(token.isSameProcess(as: .fixture(pid: 401, pidversion: 4010)))
        XCTAssertFalse(token.isSameProcess(as: .fixture(pid: 401, pidversion: 4011)))
        XCTAssertFalse(token.isSameProcess(as: .fixture(pid: 402, pidversion: 4010)))
        XCTAssertEqual(ESLoggerAuditToken(token).token, token.rowKey)
    }
}
