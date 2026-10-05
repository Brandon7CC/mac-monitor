//
//  ESAuthorizationJudgementEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
//

import Foundation
import CoreData


@objc(ESAuthorizationJudgementEvent)
public class ESAuthorizationJudgementEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case instigator
        case petitioner
        case results
        case return_code
        case result_count
        case instigator_token
        case petitioner_token
    }
    
    public var results: [ESAuthorizationResult] {
        get {
            guard let data = resultsData else { return [] }
            return (try? JSONDecoder().decode([ESAuthorizationResult].self, from: data)) ?? []
        }
        set {
            resultsData = try? JSONEncoder().encode(newValue)
        }
    }

    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: AuthorizationJudgementEvent = message.event.authorization_judgement!
        let description = NSEntityDescription.entity(forEntityName: "ESAuthorizationJudgementEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        self.return_code = Int32(event.return_code)
        self.result_count = Int32(event.result_count)
        self.results = event.results
        
        /// Each process and token on its own: Endpoint Security can leave out a process (`NULL`) and still give its
        /// token.
        let process = { (process: Process) in
            ESProcess(from: process, version: message.version, insertIntoManagedObjectContext: context)
        }
        let token = { (token: AuditToken) in ESAuditToken(from: token, insertIntoManagedObjectContext: context) }
        self.instigator = event.instigator.map(process)
        self.instigator_token = event.instigator_token.map(token)
        self.petitioner = event.petitioner.map(process)
        self.petitioner_token = event.petitioner_token.map(token)
    }
}

extension ESAuthorizationJudgementEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(return_code, forKey: .return_code)
        try container.encode(result_count, forKey: .result_count)
        try container.encode(results, forKey: .results)
        
        try container.encode(instigator, forKey: .instigator)
        try container.encode(petitioner, forKey: .petitioner)
        
        try container.encode(instigator_token, forKey: .instigator_token)
        try container.encode(petitioner_token, forKey: .petitioner_token)
    }
}
