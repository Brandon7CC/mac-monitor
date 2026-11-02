//
//  ESRemoteThreadCreateEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESRemoteThreadCreateEvent)
public class ESRemoteThreadCreateEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESProcess
    /// The thread state's `flavor`, or `nil` when the event has no thread state (`thread_create`).
    @NSManaged public var thread_state_flavor: NSNumber?
    /// The thread state's bytes in base64 (``ThreadState/state_base64``).
    @NSManaged public var thread_state_base64: String?
    /// Mac Monitor enrichment: the name of the thread state's flavor.
    @NSManaged public var thread_state_string: String?

    enum CodingKeys: CodingKey {
        case target
        case thread_state
        case thread_state_string
    }
    
    // MARK: - Custom Core Data initilizer for ESRemoteThreadCreateEvent
    convenience init(from event: RemoteThreadCreateEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.thread_state_flavor = event.thread_state.map { NSNumber(value: $0.flavor) }
        self.thread_state_base64 = event.thread_state?.state_base64
        self.thread_state_string = event.thread_state_string
        self.target = ESProcess(from: event.target, version: message.version, insertIntoManagedObjectContext: context)
    }
    
    /// The thread state, as eslogger writes it: `nil` for `thread_create`.
    public var thread_state: ThreadState? {
        thread_state_flavor.map { ThreadState(flavor: $0.int32Value, state_base64: thread_state_base64) }
    }
}

// MARK: - Encodable conformance
extension ESRemoteThreadCreateEvent: Encodable {
    /// Encode the event: eslogger's fields, `null` for no thread state, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(thread_state, forKey: .thread_state)
        try container.encode(thread_state_string, forKey: .thread_state_string)
    }
}
