//
//  FollowerRegistry.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import Combine


// MARK: - Follower registry
/// The followers of a saved set, such as ``SavedMuteSet``'s capture sessions: each is handed every change, in the
/// order they started following, until its subscription is released.
///
/// **Threading:** every call is made on the set's queue, the one given here, so the set can read its value and add a
/// follower in one step and never misses a change in between. Only a subscription's release may come from any thread:
/// it hops to the queue.
final class FollowerRegistry<Follower> {
    /// The set's queue, which every call is made on.
    private let queue: DispatchQueue
    /// The followers, by the order they started following.
    private var followers: [UInt64: Follower] = [:]
    /// The next follower's place in that order.
    private var nextID: UInt64 = 0
    
    /// - Parameter queue: The set's queue, which every call is made on.
    init(queue: DispatchQueue) {
        self.queue = queue
    }
    
    /// How many follow the set now.
    var count: Int { followers.count }
    
    /// Start handing changes to a follower. Call on the queue.
    ///
    /// - Parameter follower: Receives each later change.
    /// - Returns: The subscription, which stops the follower once it's released, on any thread. Changes already
    ///   handed to the follower may still be on their way to it.
    func add(_ follower: Follower) -> AnyCancellable {
        let id = nextID
        nextID += 1
        followers[id] = follower
        return AnyCancellable { [weak self] in self?.queue.async { self?.followers[id] = nil } }
    }
    
    /// Hand a change to every follower, in the order they started following. Call on the queue.
    ///
    /// - Parameter deliver: Hands the change to one follower.
    func notify(_ deliver: (Follower) -> Void) {
        followers.keys.sorted().forEach { id in followers[id].map(deliver) }
    }
}
