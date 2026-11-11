//
//  RawMessageFixture+Close.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - close events
extension XCTestCase {
    /// A raw close message with sequence numbers, which stays alive until the test ends. `MessageSerializer` can build
    /// it: its target is set.
    ///
    /// - Parameters:
    ///   - modified: `es_event_close_t.modified`.
    ///   - wasMappedWritable: `was_mapped_writable`, set only from message version 6, which added it.
    ///   - path: The closed file's path.
    ///   - seq: Its `seq_num`.
    ///   - global: Its `global_seq_num`.
    ///   - version: The message's version.
    /// - Returns: The message's fixture.
    func closeMessage(modified: Bool, wasMappedWritable: Bool = false, path: String = "/tmp/f", seq: UInt64 = 0,
                      global: UInt64, version: UInt32 = 10) -> RawMessageFixture {
        let fixture = sequencedMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, seq: seq, global: global, version: version)
        fixture.message.pointee.event.close.modified = modified
        fixture.message.pointee.event.close.target = fixture.file(path)
        if version >= 6 { fixture.message.pointee.event.close.was_mapped_writable = wasMappedWritable }
        return fixture
    }
}
