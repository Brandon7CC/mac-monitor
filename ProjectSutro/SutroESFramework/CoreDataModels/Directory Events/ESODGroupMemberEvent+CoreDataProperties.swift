//
//  ESODGroupMemberEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CoreData


/// The stored fields of an `od_group_add` or `od_group_remove` event besides ``ESODEvent``'s (see
/// ``OpenDirectoryGroupMemberEvent``).
extension ESODGroupMemberEvent {
    @NSManaged public var group_name: String?
    @NSManaged public var member_type: NSNumber?
    @NSManaged public var member_value: String?
    @NSManaged public var member_string: String?
}
