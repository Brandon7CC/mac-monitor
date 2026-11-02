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
public class ESAuditToken: NSManagedObject, Identifiable {
    @NSManaged public var pid: Int32
    @NSManaged public var ruid: Int64
    @NSManaged public var euid: Int64
    @NSManaged public var rgid: Int64
    @NSManaged public var egid: Int64
    @NSManaged public var asid: Int32
    @NSManaged public var auid: Int64
    @NSManaged public var pidversion: Int32

    enum CodingKeys: CodingKey {
        case pid, euid, ruid, rgid, egid, asid, auid, pidversion
    }
    
    // MARK: - Custom Core Data initilizer for ESAuditToken
    convenience init(
        from token: AuditToken,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        self.init(insertingInto: context)
        
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
    /// new row otherwise. Tokens have no `id`, so sharing them doesn't show.
    ///
    /// - Parameters:
    ///   - token: The audit token.
    ///   - context: The context to insert into.
    /// - Returns: The row, which may be a fault: attach it with ``NSManagedObject/attach(_:to:)``.
    static func row(for token: AuditToken, in context: NSManagedObjectContext) -> ESAuditToken {
        EventRowCaches.row(\.tokens, for: token.rowKey, in: context) {
            ESAuditToken(from: token, insertIntoManagedObjectContext: context)
        }
    }
    
    /// A new row for `token`, owned by the event that stores it, or `nil` without one.
    ///
    /// - Parameters:
    ///   - token: The audit token, or `nil` when Endpoint Security left it out.
    ///   - context: The context to insert into.
    /// - Returns: The new row, or `nil`.
    static func insert(_ token: AuditToken?, in context: NSManagedObjectContext) -> ESAuditToken? {
        token.map { ESAuditToken(from: $0, insertIntoManagedObjectContext: context) }
    }
}

// MARK: - Encodable conformance
extension ESAuditToken: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(pid, forKey: .pid)
        try container.encode(euid, forKey: .euid)
        try container.encode(ruid, forKey: .ruid)
        try container.encode(rgid, forKey: .rgid)
        try container.encode(egid, forKey: .egid)
        try container.encode(asid, forKey: .asid)
        try container.encode(auid, forKey: .auid)
        try container.encode(pidversion, forKey: .pidversion)
    }
}
