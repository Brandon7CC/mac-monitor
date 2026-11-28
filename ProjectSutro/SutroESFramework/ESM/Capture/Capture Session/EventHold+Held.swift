//
//  EventHold+Held.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - What waits in line
extension EventHold {
    /// An event stamped and not yet sent, whose sequence steps advance when it's sent.
    struct Stamped {
        var message: Message
        /// The set it was stamped with.
        let indicators: CompiledIndicators?
        /// The session's chains for the set's sequences, or `nil` for the set's own.
        let chains: SessionChains?
        /// The sequence steps it matched.
        var steps: ContiguousArray<Int32>
    }

    /// An answer a held event waits for.
    enum Answer {
        /// Who launched an app (``LaunchedByParentUpgrader``).
        case launchServices
        /// A written file's or a script's scan (``FileScanTicket``).
        case scan
    }

    /// An event waiting on its answers. Only touched under the hold's lock once it's in line.
    final class Held {
        var event: Stamped
        /// The answers still to come.
        var awaits: Set<Answer>
        /// The places it holds, given back as it's sent.
        let places: Set<Answer>
        /// What its answers, or giving up on them, can change.
        let changes: Set<Answer>
        /// Did an answer change it?
        var isChanged = false

        /// - Parameters:
        ///   - event: The event.
        ///   - places: The answers it has places for, and waits for.
        ///   - changes: The answers it wanted, for what can change.
        init(_ event: Stamped, places: Set<Answer>, changes: Set<Answer>) {
            self.event = event
            awaits = places
            self.places = places
            self.changes = changes
        }

        /// Are its answers in, or given up?
        var isSettled: Bool { awaits.isEmpty }

        /// Does a set read what its answers change, so the event is stamped again?
        ///
        /// - Parameter indicators: The set.
        /// - Returns: Whether it reads the launched-by parent or the scan the event waited for.
        func reads(_ indicators: CompiledIndicators) -> Bool {
            (changes.contains(.launchServices) && indicators.readsLaunchedByParent)
                || (changes.contains(.scan) && indicators.readsYaraScan)
        }
    }

    /// An event waiting in line
    enum Slot {
        case ready(CapturedEvent)
        /// An event that matched a sequence step, not encoded yet, boxed so a slot stays small
        indirect case stamped(Stamped)
        case held(Held)
    }
}
