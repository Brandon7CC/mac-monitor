//
//  ESSetModeEvent+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//
//

import Foundation
import CoreData


@objc(ESSetModeEvent)
public class ESSetModeEvent: NSManagedObject, Identifiable {
    @NSManaged public var mode: Int32
    @NSManaged public var target: ESFile

    enum CodingKeys: CodingKey {
        case mode
        case target
        case mode_symbolic
        case previous_mode
        case mode_added
    }
    
    // MARK: - Custom Core Data initilizer for ESSetModeEvent
    convenience init(from event: SetModeEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.mode = event.mode
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESSetModeEvent.target))
    }
}

// MARK: - Mac Monitor enrichment
/// Derived from the stored mode and the target's stat when read or written, not stored, as ``ESMMapEvent``'s names
/// are: an eslogger trace, a trace exported before Mac Monitor 3.1.0, or an event from a 3.0.0 Security Extension
/// gets them too. The Event Facts show the same values.
extension ESSetModeEvent {
    /// The mode the file was given.
    public var fileMode: FileMode {
        FileMode(mode)
    }

    /// The mode the file had: Endpoint Security's stat of the target is from before the change. `nil` without a stat.
    public var previousFileMode: FileMode? {
        target.stat.flatMap { FileMode(statMode: $0.st_mode) }
    }

    /// What the change added that's worth pointing out (``FileModeCallout/added(to:from:)``).
    public var addedCallouts: [FileModeCallout] {
        FileModeCallout.added(to: fileMode, from: previousFileMode)
    }
}

// MARK: - Encodable conformance
extension ESSetModeEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(target, forKey: .target)
        /// Derived when written, from the mode and the target's stat: not stored. `previous_mode` is always written,
        /// `null` without a stat.
        try container.encode(fileMode.symbolic, forKey: .mode_symbolic)
        try container.encode(previousFileMode.map { Int($0.permissions) }, forKey: .previous_mode)
        try container.encode(addedCallouts.map(\.telemetryName), forKey: .mode_added)
    }
}
