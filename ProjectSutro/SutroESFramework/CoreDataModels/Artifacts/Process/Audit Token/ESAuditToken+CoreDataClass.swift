//
//  ESAuditToken+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//
//

import Foundation
import CoreData

@objc(ESAuditToken)
public class ESAuditToken: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, pid, euid, ruid, rgid, egid, asid, auid, pidversion
    }
    
    // MARK: - Custom Core Data initilizer for ESAuditToken
    convenience init(
        from token: AuditToken,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESAuditToken", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = token.id
        
        self.pid = token.pid
        self.euid = token.euid
        self.ruid = token.ruid
        self.rgid = token.rgid
        self.egid = token.egid
        self.asid = token.asid
        self.auid = token.auid
        self.pidversion = token.pidversion
    }
    
    /// The row for `token`: shared with every other use of the same token when `context` has ``EventRowCaches``, or a
    /// new row otherwise. Tokens don't export their `id`, so sharing them doesn't show.
    ///
    /// - Parameters:
    ///   - token: The audit token.
    ///   - context: The context to insert into.
    /// - Returns: The row, which may be a fault: attach it with ``NSManagedObject/attach(_:to:)``.
    static func row(for token: AuditToken, in context: NSManagedObjectContext) -> ESAuditToken {
        EventRowCaches.row(\.tokens, for: token.rowKey, in: context) { ESAuditToken(from: token, insertIntoManagedObjectContext: context) }
    }
}

// MARK: - Encodable conformance and helper
extension ESAuditToken: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        try container.encode(pid, forKey: .pid)
        try container.encode(euid, forKey: .euid)
        try container.encode(ruid, forKey: .ruid)
        try container.encode(rgid, forKey: .rgid)
        try container.encode(egid, forKey: .egid)
        try container.encode(asid, forKey: .asid)
        try container.encode(auid, forKey: .auid)
        try container.encode(pidversion, forKey: .pidversion)
    }
    
    public func toString() -> String {
        return "pid:\(pid), euid:\(euid), ruid:\(ruid), rgid:\(rgid), egid:\(egid), asid:\(asid), auid:\(auid), pidversion:\(pidversion)"
    }
}
