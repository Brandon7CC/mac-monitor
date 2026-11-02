//
//  ESMessage+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Launched by parent
extension ESMessage {
    /// Did this event create a process? An exec (its target) and a fork (its child) do.
    public var createsProcess: Bool {
        event_type == Self.execEventType || event_type == Self.forkEventType
    }
    
    /// The launched-by parent of the process this event created (an exec's target or a fork's child), as stored. `nil`
    /// for any other event, and for one without an answer.
    public var createdLaunchedByParent: LaunchedByParent? {
        switch event_type {
        case Self.execEventType: event.exec?.launched_by_parent
        case Self.forkEventType: event.fork?.launched_by_parent
        default: nil
        }
    }
}
