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
public class ESRemoteThreadCreateEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case target
        case thread_state
        case thread_state_string
    }
    
    // MARK: - Custom Core Data initilizer for ESRemoteThreadCreateEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let threadEvent: RemoteThreadCreateEvent = message.event.remote_thread_create!
        let description = NSEntityDescription.entity(forEntityName: "ESRemoteThreadCreateEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = threadEvent.id
        self.thread_state_flavor = threadEvent.thread_state.map { NSNumber(value: $0.flavor) }
        self.thread_state_base64 = threadEvent.thread_state?.state_base64
        self.thread_state_string = threadEvent.thread_state_string
        self.target = ESProcess(from: threadEvent.target, version: message.version, insertIntoManagedObjectContext: context)
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
