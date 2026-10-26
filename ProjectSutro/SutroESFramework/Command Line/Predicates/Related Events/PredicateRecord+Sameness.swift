//
//  PredicateRecord+Sameness.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Same event
/// Which of a group's kept events are which event (``PredicateRecord/isSame(as:)``): by their storage, and by their
/// type, sequence number and time, compared as `isEqual(_:)` compares them.
struct Sameness {
    /// An event's type, sequence number and time, if it has all three (`null` counts).
    struct Identity: Hashable {
        let values: [NSObject]
        
        /// - Parameter record: An event's record.
        init?(_ record: NSDictionary) {
            var values: [NSObject] = []
            for key in PredicateRecord.identityKeys {
                guard let value = record[key] as? NSObject else { return nil }
                values.append(value)
            }
            self.values = values
        }
    }
    
    private var byStorage: [ObjectIdentifier: [Int]] = [:]
    private var byIdentity: [Identity: [Int]] = [:]
    
    /// - Parameter records: A group's events, in order.
    init(_ records: [PredicateRecord]) {
        for (index, record) in records.enumerated() {
            byStorage[ObjectIdentifier(record.values), default: []].append(index)
            if let identity = Identity(record.values) { byIdentity[identity, default: []].append(index) }
        }
    }
    
    /// - Parameter searched: The searched event.
    /// - Returns: The indexes of the group's events that are the same event, ascending.
    func indexes(of searched: PredicateRecord) -> [Int] {
        let identical = Identity(searched.values).flatMap { byIdentity[$0] } ?? []
        return Set(identical + (byStorage[ObjectIdentifier(searched.values)] ?? [])).sorted()
    }
}


/// Records without some of them, read in place, as `NSPredicate` reads a `SUBQUERY`'s related events.
final class SkippingArray: NSArray {
    private var records: [PredicateRecord] = []
    /// The indexes left out, ascending.
    private var skipped: [Int] = []
    
    /// - Parameters:
    ///   - records: The records.
    ///   - skipped: The indexes left out, ascending.
    convenience init(_ records: [PredicateRecord], skipping skipped: [Int]) {
        self.init()
        self.records = records
        self.skipped = skipped
    }
    
    override init() { super.init() }
    override init(objects: UnsafePointer<AnyObject>?, count: Int) { super.init(objects: objects, count: count) }
    required init?(coder: NSCoder) { nil }
    
    override var count: Int { records.count - skipped.count }
    
    /// - Parameter index: A position among the records left in.
    /// - Returns: The record there.
    override func object(at index: Int) -> Any {
        var position = index
        for skip in skipped where skip <= position { position += 1 }
        return records[position]
    }
}


extension PredicateRecord {
    /// The keys that tell one event from another (``isSame(as:)``).
    static let identityKeys = ["mach_time", "global_seq_num", "es_event_type"]

    /// Is this the same event as another, by its type, sequence number and time? A searched event isn't related to
    /// itself.
    ///
    /// - Parameter other: Another record.
    /// - Returns: `true` if both have the same `es_event_type`, `global_seq_num` and `mach_time`.
    func isSame(as other: PredicateRecord) -> Bool {
        values === other.values || Sameness.Identity(values).map { $0 == Sameness.Identity(other.values) } ?? false
    }
}
