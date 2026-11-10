//
//  FollowerRegistryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import Combine
@testable import SutroESFramework


// MARK: - Followers of a saved set
/// Pins how a saved set hands out changes: in the order followers started, until each subscription is released, and
/// a release from any thread takes effect on the set's queue.
final class FollowerRegistryTests: XCTestCase {
    /// The set's queue.
    private let queue = DispatchQueue(label: "FollowerRegistryTests")
    
    /// Followers are handed each change in the order they started following, whatever their identities hash to.
    func testChangesGoOutInFollowOrder() {
        let registry = FollowerRegistry<(Int) -> Void>(queue: queue)
        var heard: [String] = []
        let subscriptions = queue.sync {
            (0..<20).map { follower in registry.add { heard.append("\(follower):\($0)") } }
        }
        queue.sync { registry.notify { $0(1) } }
        queue.sync { registry.notify { $0(2) } }
        XCTAssertEqual(heard, (1...2).flatMap { change in (0..<20).map { "\($0):\(change)" } })
        XCTAssertEqual(subscriptions.count, 20)
    }
    
    /// A released subscription stops its follower once the queue gets to it, wherever it was released, and leaves
    /// the rest following.
    func testAReleaseStopsOnlyThatFollower() {
        let registry = FollowerRegistry<(Int) -> Void>(queue: queue)
        var heard: [Int] = []
        var first: AnyCancellable? = queue.sync { registry.add { heard.append($0) } }
        let second = queue.sync { registry.add { heard.append(-$0) } }
        XCTAssertEqual(queue.sync { registry.count }, 2)
        
        let released = expectation(description: "released")
        DispatchQueue.global().async {
            first = nil
            released.fulfill()
        }
        wait(for: [released], timeout: 5)
        queue.sync {}
        XCTAssertNil(first)
        XCTAssertEqual(queue.sync { registry.count }, 1)
        queue.sync { registry.notify { $0(7) } }
        XCTAssertEqual(heard, [-7])
        second.cancel()
        queue.sync {}
        XCTAssertEqual(queue.sync { registry.count }, 0)
    }
    
    /// A subscription that outlives its registry releases without effect.
    func testAReleaseAfterTheRegistryIsGoneDoesNothing() {
        var registry: FollowerRegistry<() -> Void>? = FollowerRegistry(queue: queue)
        weak var gone = registry
        let subscription = queue.sync { registry!.add {} }
        registry = nil
        XCTAssertNil(gone)
        subscription.cancel()
        queue.sync {}
    }
}
