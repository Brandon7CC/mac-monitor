//
//  ESProcessExitEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData
import OSLog

@objc(ESProcessExitEvent)
public class ESProcessExitEvent: NSManagedObject, Identifiable {
    @NSManaged public var stat: Int32

    enum CodingKeys: CodingKey {
        case stat
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessExitEvent
    convenience init(from event: ProcessExitEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.stat = Int32(truncatingIfNeeded: event.stat)
    }
}

// MARK: - Encodable conformance
extension ESProcessExitEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(stat, forKey: .stat)
    }
}
