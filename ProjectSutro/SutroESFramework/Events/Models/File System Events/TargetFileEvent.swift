//
//  TargetFileEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Endpoint Security's events about one file
/// The field an `es_event_write_t`, `es_event_dup_t` and `es_event_listextattr_t` share.
protocol TargetFileFields {
    /// The file written, duplicated, or whose extended attributes are listed.
    var target: UnsafeMutablePointer<es_file_t> { get }
}

extension es_event_write_t: TargetFileFields {}
extension es_event_dup_t: TargetFileFields {}
extension es_event_listextattr_t: TargetFileFields {}


// MARK: - Target file event
// https://developer.apple.com/documentation/endpointsecurity/es_event_write_t
// https://developer.apple.com/documentation/endpointsecurity/es_event_dup_t
// https://developer.apple.com/documentation/endpointsecurity/es_event_listextattr_t
/// Models an `ES_EVENT_TYPE_NOTIFY_WRITE`, `ES_EVENT_TYPE_NOTIFY_DUP` or `ES_EVENT_TYPE_NOTIFY_LISTEXTATTR`: a process
/// wrote a file, duplicated a descriptor of it, or listed its extended attributes.
public struct TargetFileEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()

    public var target: File

    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter event: The message's `write`, `dup` or `listextattr`.
    init(from event: some TargetFileFields) {
        target = File(from: event.target.pointee)
    }
}
