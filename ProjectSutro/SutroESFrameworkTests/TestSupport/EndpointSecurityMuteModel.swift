//
//  EndpointSecurityMuteModel.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Endpoint Security's path mutes, modeled
/// A client's path mutes as `ESClient.h` describes them: a set of (type, path, event) tuples. Muting adds tuples,
/// unmuting subtracts them, and "every event" is every event of ``universe``.
struct EndpointSecurityMuteModel: Equatable {
    /// One muted (type, path, event).
    struct Tuple: Hashable {
        let key: MuteList.Key
        let event: es_event_type_t
    }
    
    /// Every event the model knows: what `es_mute_path` and `es_unmute_path` cover.
    let universe: Set<es_event_type_t>
    /// The muted tuples.
    private(set) var tuples: Set<Tuple> = []
    
    /// - Parameter universe: Every event the model knows.
    init(universe: Set<es_event_type_t>) {
        self.universe = universe
    }
    
    /// A client with a list's mutes and nothing else.
    ///
    /// - Parameters:
    ///   - list: The list.
    ///   - universe: Every event the model knows.
    init(_ list: MuteList, universe: Set<es_event_type_t>) {
        self.init(universe: universe)
        list.mutes.forEach { apply(MuteChange($0, muted: true)) }
    }
    
    /// Make one call: `es_mute_path` / `es_mute_path_events`, or their unmute counterparts.
    ///
    /// - Parameter change: The call.
    mutating func apply(_ change: MuteChange) {
        let key = MuteList.Key(path: change.mute.path, type: change.mute.type)
        let events = change.mute.events.isEmpty ? universe : Set(change.mute.events)
        let affected = Set(events.map { Tuple(key: key, event: $0) })
        if change.muted {
            tuples.formUnion(affected)
        } else {
            tuples.subtract(affected)
        }
    }
}


// MARK: - Seeded randomness
/// A SplitMix64 generator, so a property test draws the same cases on every run.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64
    
    /// - Parameter seed: The seed.
    init(seed: UInt64) {
        state = seed
    }
    
    /// The next 64 random bits.
    ///
    /// - Returns: The bits.
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}
