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
public class ESAuthorizationJudgementEvent: NSManagedObject, Identifiable {
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var petitioner: ESProcess?
    @NSManaged public var resultsData: Data?
    @NSManaged public var return_code: Int32
    @NSManaged public var result_count: Int32
    
    @NSManaged public var instigator_token: ESAuditToken?
    @NSManaged public var petitioner_token: ESAuditToken?

    enum CodingKeys: CodingKey {
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

    convenience init(from event: AuthorizationJudgementEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.return_code = Int32(event.return_code)
        self.result_count = Int32(event.result_count)
        self.results = event.results
        
        /// Each process and token on its own: Endpoint Security can leave out a process (`NULL`) and still give its
        /// token.
        self.instigator = ESProcess.insert(event.instigator, version: message.version, in: context)
        self.instigator_token = ESAuditToken.insert(event.instigator_token, in: context)
        self.petitioner = ESProcess.insert(event.petitioner, version: message.version, in: context)
        self.petitioner_token = ESAuditToken.insert(event.petitioner_token, in: context)
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
