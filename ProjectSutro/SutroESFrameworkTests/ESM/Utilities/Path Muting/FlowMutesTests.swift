//
//  FlowMutesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mutes for network flows
/// Pins which mutes the network lane applies to a flow's process: process mutes for every event or naming the flow's
/// event, byte for byte, and never a target mute or a flow whose path isn't known.
final class FlowMutesTests: XCTestCase {
    /// A literal mute for every event covers both flow events, and only its path.
    func testLiteralMutes() {
        let mutes = FlowMutes(MuteList([PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL)]))
        for event in MacMonitorEvent.allCases {
            XCTAssertTrue(mutes.mutes("/usr/libexec/logd", for: event))
            XCTAssertFalse(mutes.mutes("/usr/libexec/logd2", for: event))
            XCTAssertFalse(mutes.mutes("/usr/libexec", for: event))
            XCTAssertFalse(mutes.mutes(nil, for: event), "A flow whose path isn't known is never muted")
        }
    }

    /// A prefix mute covers every path it starts. One scoped to `new_flow` leaves `flow_closed` alone, and one scoped
    /// only to Endpoint Security events covers neither.
    func testPrefixesAndScopes() {
        let mutes = FlowMutes(MuteList([
            PathMute(path: "/System/Library/PrivateFrameworks/", type: ES_MUTE_PATH_TYPE_PREFIX),
            PathMute(path: "/usr/bin/", type: ES_MUTE_PATH_TYPE_PREFIX, events: [MacMonitorEvent.new_flow.type]),
            PathMute(path: "/usr/sbin/", type: ES_MUTE_PATH_TYPE_PREFIX, events: [ES_EVENT_TYPE_NOTIFY_EXEC]),
        ]))
        let framework = "/System/Library/PrivateFrameworks/Metadata.framework/Versions/A/Support/mdworker_shared"
        XCTAssertTrue(mutes.mutes(framework, for: .new_flow))
        XCTAssertTrue(mutes.mutes(framework, for: .flow_closed))
        XCTAssertTrue(mutes.mutes("/usr/bin/curl", for: .new_flow))
        XCTAssertFalse(mutes.mutes("/usr/bin/curl", for: .flow_closed))
        XCTAssertFalse(mutes.mutes("/usr/sbin/mDNSResponder", for: .new_flow))
    }

    /// A target mute never applies: a flow has no target path.
    func testTargetMutesNeverApply() {
        let mutes = FlowMutes(MuteList([
            PathMute(path: "/usr/bin/curl", type: ES_MUTE_PATH_TYPE_TARGET_LITERAL),
            PathMute(path: "/usr/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX),
        ]))
        XCTAssertEqual(mutes, FlowMutes())
        XCTAssertFalse(mutes.mutes("/usr/bin/curl", for: .new_flow))
    }

    /// Paths compare byte for byte, as Endpoint Security compares them: a path in NFD isn't muted by the same path
    /// in NFC, though Swift's strings take the two as equal.
    func testPathsCompareByteForByte() {
        let literal = FlowMutes(MuteList([PathMute(path: CanonicalSpellings.nfc, type: ES_MUTE_PATH_TYPE_LITERAL)]))
        XCTAssertTrue(literal.mutes(CanonicalSpellings.nfc, for: .new_flow))
        XCTAssertFalse(literal.mutes(CanonicalSpellings.nfd, for: .new_flow))
        let prefix = FlowMutes(MuteList([PathMute(path: CanonicalSpellings.nfd, type: ES_MUTE_PATH_TYPE_PREFIX)]))
        XCTAssertTrue(prefix.mutes(CanonicalSpellings.nfd + "/tool", for: .new_flow))
        XCTAssertFalse(prefix.mutes(CanonicalSpellings.nfc + "/tool", for: .new_flow))
    }

    /// The default mute set's processes muted for every event have their flows muted too.
    func testTheDefaultSetMutesItsProcessesFlows() {
        let mutes = FlowMutes(MuteList.shippedDefault(for: nil))
        XCTAssertTrue(mutes.mutes("/usr/libexec/logd", for: .new_flow))
        XCTAssertTrue(mutes.mutes("/usr/libexec/logd", for: .flow_closed))
    }
}
