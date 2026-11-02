//
//  XattrEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Endpoint Security's extended attribute events
/// The fields an `es_event_setextattr_t`, `es_event_getextattr_t` and `es_event_deleteextattr_t` share.
protocol XattrFields {
    /// The file whose extended attribute is set, read or deleted.
    var target: UnsafeMutablePointer<es_file_t> { get }
    /// The extended attribute's name.
    var extattr: es_string_token_t { get }
}

extension es_event_setextattr_t: XattrFields {}
extension es_event_getextattr_t: XattrFields {}
extension es_event_deleteextattr_t: XattrFields {}


// MARK: - Extended attribute event
// https://developer.apple.com/documentation/endpointsecurity/es_event_setextattr_t
// https://developer.apple.com/documentation/endpointsecurity/es_event_getextattr_t
// https://developer.apple.com/documentation/endpointsecurity/es_event_deleteextattr_t
/// Models an `ES_EVENT_TYPE_NOTIFY_SETEXTATTR`, `ES_EVENT_TYPE_NOTIFY_GETEXTATTR` or
/// `ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR`: a process set, read or deleted an extended attribute of a file.
public struct XattrEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()

    public var target: File
    public var extattr: String

    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter event: The message's `setextattr`, `getextattr` or `deleteextattr`.
    init(from event: some XattrFields) {
        target = File(from: event.target.pointee)
        extattr = event.extattr.string ?? ""
    }
}
