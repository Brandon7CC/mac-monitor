//
//  ESUIPCBindEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/1/25.
//
//

import Foundation
import CoreData


@objc(ESUIPCBindEvent)
public class ESUIPCBindEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case dir
        case filename
        case mode
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: UIPCBindEvent = message.event.uipc_bind!
        let description = NSEntityDescription.entity(forEntityName: "ESUIPCBindEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.dir, in: context), to: #keyPath(ESUIPCBindEvent.dir))
        self.filename = event.filename
        self.mode = event.mode
    }
}

extension ESUIPCBindEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(dir, forKey: .dir)
        try container.encode(filename, forKey: .filename)
        try container.encode(mode, forKey: .mode)
    }
}

