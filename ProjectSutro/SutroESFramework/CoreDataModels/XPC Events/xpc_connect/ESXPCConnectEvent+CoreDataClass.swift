//
//  ESXPCConnectEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/24/23.
//
//

import Foundation
import CoreData

@objc(ESXPCConnectEvent)
public class ESXPCConnectEvent: NSManagedObject, Identifiable {
    @NSManaged public var service_name: String
    @NSManaged public var service_domain_type: Int32
    @NSManaged public var service_domain_type_string: String

    enum CodingKeys: CodingKey {
        case service_name, service_domain_type, service_domain_type_string
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let xpcConnectEvent: XPCConnectEvent = message.event.xpc_connect!
        let description = NSEntityDescription.entity(forEntityName: "ESXPCConnectEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.service_name = xpcConnectEvent.service_name
        self.service_domain_type = xpcConnectEvent.service_domain_type
        self.service_domain_type_string = xpcConnectEvent.service_domain_type_string
    }
}

extension ESXPCConnectEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(service_name, forKey: .service_name)
        try container.encode(service_domain_type, forKey: .service_domain_type)
        try container.encode(service_domain_type_string, forKey: .service_domain_type_string)
    }
}

