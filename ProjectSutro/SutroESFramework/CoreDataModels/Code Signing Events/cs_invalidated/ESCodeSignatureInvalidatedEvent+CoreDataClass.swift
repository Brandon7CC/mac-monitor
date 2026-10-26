//
//  ESCodeSignatureInvalidatedEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESCodeSignatureInvalidatedEvent)
public class ESCodeSignatureInvalidatedEvent: NSManagedObject, Identifiable {
    enum CodingKeys: CodingKey {}
    
    // MARK: - Custom Core Data initilizer for ESCodeSignatureInvalidatedEvent
    convenience init(from event: CodeSignatureInvalidatedEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
    }
}

// MARK: - Encodable conformance
extension ESCodeSignatureInvalidatedEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        _ = encoder.container(keyedBy: CodingKeys.self)
    }
}
