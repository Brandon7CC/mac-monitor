//
//  ESThread+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/18/25.
//
//

import Foundation
import CoreData

@objc(ESThread)
public class ESThread: NSManagedObject, Identifiable {
    @NSManaged public var thread_id: Int64

    enum CodingKeys: String, CodingKey {
        case thread_id
    }

    convenience init(from thread: SutroESFramework.Thread, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.thread_id = Int64(thread.thread_id)
    }
}

// MARK: - Encodable conformance
extension ESThread: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(thread_id, forKey: .thread_id)
    }
}
