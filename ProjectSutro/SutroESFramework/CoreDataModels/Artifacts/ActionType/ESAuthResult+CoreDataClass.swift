//
//  ESAuthResult+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/1/25.
//
//

import Foundation
import CoreData

@objc(ESAuthResult)
public class ESAuthResult: NSManagedObject, Decodable {
    enum CodingKeys: CodingKey {
        case id
        case auth, auth_human
        case flags
    }
    
    // MARK: - Custom initilizer for ESAuthResult
    convenience init(from authResult: AuthResult) {
        self.init()
        self.id = authResult.id
        
        // If the action result type is `AUTH`
        if let auth = authResult.auth,
           let auth_human = authResult.auth_human {
            self.auth = Int64(auth)
            self.auth_human = auth_human
        }
        
        // If the action result type is `FLAGS`
        if let flags = authResult.flags {
            self.flags = flags
        }
        
    }
    
    // MARK: - Custom Core Data initilizer for ESAuthResult
    convenience init(
        from authResult: AuthResult,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESAuthResult", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = authResult.id
        
        // If the action result type is `AUTH`
        if let auth = authResult.auth,
           let auth_human = authResult.auth_human {
            self.auth = Int64(auth)
            self.auth_human = auth_human
        }
        
        // If the action result type is `FLAGS`
        if let flags = authResult.flags {
            self.flags = flags
        }
    }
    
    // MARK: - Decodable conformance
    required convenience public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init()
        
        try id = container.decode(UUID.self, forKey: .id)
        
        // If the action result type is `AUTH`
        try auth_human = container.decodeIfPresent(String.self, forKey: .auth_human)
        try auth = container.decode(Int64.self, forKey: .auth)
        
        // If the action result type is `FLAGS`
        try flags = container.decode(Int64.self, forKey: .flags)
        
    }

}

extension ESAuthResult: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        
        if let auth_human = auth_human {
            try container.encode(auth_human, forKey: .auth_human)
            try container.encode(auth, forKey: .auth)
        } else {
            try container.encode(flags, forKey: .flags)
        }
    }
}
