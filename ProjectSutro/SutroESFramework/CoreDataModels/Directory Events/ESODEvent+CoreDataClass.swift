//
//  ESODEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CoreData


/// The fields every stored Open Directory event has (an abstract entity: each event type is a sub-entity).
@objc(ESODEvent)
public class ESODEvent: NSManagedObject {
    /// Store the fields every Open Directory event has.
    ///
    /// The instigator and its audit token get rows of their own rather than rows shared through ``EventRowCaches``:
    /// their relationships have inverses, which ``NSManagedObject/attach(_:to:)`` doesn't keep up to date. Open
    /// Directory events are rare, so the rows cost little.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - version: The message's version.
    ///   - context: The context this object is in.
    func store(_ event: some OpenDirectoryEvent, version: Int, in context: NSManagedObjectContext) {
        id = event.id
        if let process = event.instigator {
            instigator = ESProcess(from: process, version: version, insertIntoManagedObjectContext: context)
        }
        if let token = event.instigator_token {
            instigator_token = ESAuditToken(from: token, insertIntoManagedObjectContext: context)
        }
        error_code = Int32(truncatingIfNeeded: event.error_code)
        node_name = event.node_name
        db_path = event.db_path
        
        error_code_human = event.error_code_human
        instigator_process_name = event.instigator_process_name
        instigator_process_path = event.instigator_process_path
        instigator_process_signing_id = event.instigator_process_signing_id
        instigator_process_audit_token = event.instigator_process_audit_token
    }
    
    /// Encode the fields every Open Directory event has: eslogger's, then Mac Monitor's. A sub-entity encodes its own
    /// fields into the same object.
    ///
    /// `instigator` is `null` when Endpoint Security left it out, as eslogger writes it, and so is `instigator_token`
    /// before message version 8 and in events recorded before 2.2.0, which Mac Monitor didn't keep.
    ///
    /// - Parameter encoder: The event's encoder.
    /// - Throws: The error encoding a field.
    func encodeCommonFields(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: ODEventKeys.self)
        try container.encode(instigator, forKey: .instigator)
        try container.encode(error_code, forKey: .error_code)
        try container.encode(node_name, forKey: .node_name)
        try container.encode(db_path, forKey: .db_path)
        try container.encode(instigator_token, forKey: .instigator_token)
        
        try container.encode(error_code_human, forKey: .error_code_human)
        try container.encode(instigator_process_name, forKey: .instigator_process_name)
        try container.encode(instigator_process_path, forKey: .instigator_process_path)
        try container.encode(instigator_process_signing_id, forKey: .instigator_process_signing_id)
        try container.encode(instigator_process_audit_token, forKey: .instigator_process_audit_token)
    }
}
