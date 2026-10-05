//
//  OpenDirectoryMemberTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Members and enum names
/// Pins how an `od_group_add` or `od_group_remove` event's member is read and written (eslogger's
/// `{member_type, member_value}`), and the names Mac Monitor gives Open Directory enums, which were its only record of
/// them before 2.2.0 and are kept in the `*_string` fields.
final class OpenDirectoryMemberTests: XCTestCase {
    /// The UUID eslogger wrote for a user in the fixture's `od_group_add` event.
    private static let userUUID = "0A0A0A0A-1B1B-4C2C-8D3D-00000000A001"
    /// The UUID eslogger wrote for the `staff` group.
    private static let groupUUID = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014"
    
    // MARK: Enum names
    
    /// The SDK's raw values, which eslogger writes and Mac Monitor now keeps.
    func testSDKRawValues() {
        XCTAssertEqual([ES_OD_MEMBER_TYPE_USER_NAME, ES_OD_MEMBER_TYPE_USER_UUID, ES_OD_MEMBER_TYPE_GROUP_UUID]
            .map(\.rawValue), [0, 1, 2])
        XCTAssertEqual([ES_OD_RECORD_TYPE_USER, ES_OD_RECORD_TYPE_GROUP].map(\.rawValue), [0, 1])
        XCTAssertEqual([ES_OD_ACCOUNT_TYPE_USER, ES_OD_ACCOUNT_TYPE_COMPUTER].map(\.rawValue), [0, 1])
    }
    
    /// Each value is named as Mac Monitor named it before 2.2.0, and a value the SDK doesn't define as it did then.
    func testNames() {
        let memberType = ODEnumNames.memberType, recordType = ODEnumNames.recordType
        let accountType = ODEnumNames.accountType
        XCTAssertEqual((0...3).map(memberType.name(of:)), ["ES_OD_MEMBER_TYPE_USER_NAME", "ES_OD_MEMBER_TYPE_USER_UUID",
                                                           "ES_OD_MEMBER_TYPE_GROUP_UUID", "UNKNOWN"])
        XCTAssertEqual((0...2).map(recordType.name(of:)), ["USER", "GROUP", "UNKNOWN"])
        XCTAssertEqual((0...2).map(accountType.name(of:)),
                       ["ES_OD_ACCOUNT_TYPE_USER", "ES_OD_ACCOUNT_TYPE_COMPUTER", "UNKNOWN_ACCOUNT_TYPE"])
        XCTAssertEqual(memberType.name(of: 7), "UNKNOWN")
    }
    
    /// A name reads back as its value, and the name of an unknown value as none.
    func testRawValuesOfNames() {
        for names in [ODEnumNames.memberType, .recordType, .accountType] {
            for value in names.names.keys {
                XCTAssertEqual(names.rawValue(of: names.name(of: value)), value)
            }
            XCTAssertNil(names.rawValue(of: names.unknown))
            XCTAssertNil(names.rawValue(of: "0"))
        }
    }
    
    // MARK: Members
    
    /// A member as Endpoint Security names it.
    ///
    /// - Parameters:
    ///   - type: The member's `es_od_member_type_t`.
    ///   - value: The user's name for type 0, or the UUID for types 1 and 2. `nil` leaves the name `NULL`.
    /// - Returns: Mac Monitor's member.
    private func member(type: Int, value: String?) -> OpenDirectoryMember {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD)
        let event = fixture.odEvent(\.od_group_add)
        fixture.setMember(of: event, type: type, value: value)
        return OpenDirectoryMember(from: event.pointee.member.pointee)
    }
    
    /// A user's name is read from the union's `name`, and a UUID from its `uuid`, in uppercase as eslogger writes it.
    func testMemberValues() {
        XCTAssertEqual(member(type: 0, value: "testuser"),
                       OpenDirectoryMember(member_type: 0, member_value: "testuser"))
        XCTAssertEqual(member(type: 1, value: Self.userUUID.lowercased()),
                       OpenDirectoryMember(member_type: 1, member_value: Self.userUUID))
        XCTAssertEqual(member(type: 2, value: Self.groupUUID),
                       OpenDirectoryMember(member_type: 2, member_value: Self.groupUUID))
    }
    
    /// A type the SDK doesn't define has no value to read (eslogger writes no event then), and a `NULL` name none.
    func testMemberWithoutValue() {
        XCTAssertEqual(member(type: 7, value: nil), OpenDirectoryMember(member_type: 7, member_value: nil))
        XCTAssertEqual(member(type: 0, value: nil), OpenDirectoryMember(member_type: 0, member_value: nil))
    }
    
    /// A member without a value is written with `member_value: null`, as eslogger writes every key it has.
    ///
    /// - Throws: The error encoding or parsing the member.
    func testMemberEncodesNull() throws {
        let data = try JSONEncoder().encode(OpenDirectoryMember(member_type: 1, member_value: nil))
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object.keys.sorted(), ["member_type", "member_value"])
        XCTAssertTrue(object["member_value"] is NSNull)
        XCTAssertEqual(try JSONDecoder().decode(OpenDirectoryMember.self, from: data),
                       OpenDirectoryMember(member_type: 1, member_value: nil))
    }
}
