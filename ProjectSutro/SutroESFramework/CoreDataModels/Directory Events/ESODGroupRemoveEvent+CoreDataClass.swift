//
//  ESODGroupRemoveEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData


/// A stored `od_group_remove` event.
@objc(ESODGroupRemoveEvent)
public class ESODGroupRemoveEvent: ESODGroupMemberEvent {
    /// Store an event.
    ///
    /// - Parameters:
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let description = NSEntityDescription.entity(forEntityName: "ESODGroupRemoveEvent", in: context)!
        self.init(entity: description, insertInto: context)
        store(groupMember: message.event.od_group_remove!, version: message.version, in: context)
    }
}
