//
//  ESODGroupAddEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData


/// A stored `od_group_add` event.
@objc(ESODGroupAddEvent)
public class ESODGroupAddEvent: ESODGroupMemberEvent, Identifiable {
    /// Store an event.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from event: OpenDirectoryGroupAddEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        store(groupMember: event, version: message.version, in: context)
    }
}
