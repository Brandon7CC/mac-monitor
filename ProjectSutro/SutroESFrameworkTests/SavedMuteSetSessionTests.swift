//
//  SavedMuteSetSessionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Sessions following the saved mute set
/// Pins how the saved mute set reaches capture: every session that follows it starts with it and gets exactly each
/// change on all of its clients, live; a session that doesn't follow it (`--no-mutes`), or no longer does, gets
/// nothing.
final class SavedMuteSetSessionTests: XCTestCase {
    /// A session and the factory holding its fake clients.
    private struct Follower {
        let session: CaptureSession
        let factory: FakeEndpointSecurityClientFactory
        let subscription: MuteSubscription?
    }
    
    /// Lets a follower closure reach a session made after it.
    private final class SessionBox {
        var session: CaptureSession?
    }
    
    private var saved = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    
    /// A saved set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        saved = SavedMuteSet(testing: try makeMuteStore())
    }
    
    /// A session on fake clients, following the saved set the way the Security Extension's sessions do: the set
    /// read and followed at once, then given to the session's configuration. The follower applies changes
    /// synchronously, since the test drives the session from no other queue.
    ///
    /// - Parameter following: Follow the saved set, or start without mutes as `--no-mutes` does.
    /// - Returns: The session, its factory, and its subscription.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    private func makeFollower(following: Bool = true) throws -> Follower {
        let box = SessionBox()
        var configuration = CaptureConfiguration(label: "Test")
        var subscription: MuteSubscription?
        if following {
            let (mutes, followed) = saved.follow { list, _ in box.session?.applyMutes(list) }
            configuration.mutes = mutes
            subscription = followed
        }
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(configuration, factory: factory)
        box.session = session
        return Follower(session: session, factory: factory, subscription: subscription)
    }
    
    /// Send a request and wait until every follower has the result.
    ///
    /// - Parameters:
    ///   - operation: What to do.
    ///   - mutes: The entries.
    ///   - access: What the caller may do.
    /// - Returns: The reply's status.
    @discardableResult
    private func send(_ operation: MuteRequest.Operation, _ mutes: [MuteFile.Entry] = [],
                      access: MuteAccess = .write) -> MuteReply.Status? {
        var status: MuteReply.Status?
        saved.handle(MuteRequest(operation, mutes).encoded(), access: access, caller: "Test") {
            status = MuteReply.decode($0)?.status
        }
        saved.waitUntilIdle()
        return status
    }
    
    /// Path mute calls since a point, per client.
    ///
    /// - Parameters:
    ///   - follower: The session.
    ///   - start: Each client's call count at that point.
    /// - Returns: Each client's path mute calls since.
    private func pathMutes(of follower: Follower, since start: [Int]) -> [[FakeEndpointSecurityClient.Call]] {
        zip(follower.factory.clients, start).map { client, start in
            client.calls.dropFirst(start).filter { $0.kind == .setPathMute }
        }
    }
    
    /// Calls for some changes.
    ///
    /// - Parameter changes: The changes.
    /// - Returns: The calls each client should get.
    private func calls(_ changes: [MuteChange]) -> [FakeEndpointSecurityClient.Call] {
        changes.map { .setPathMute($0.mute, muted: $0.muted) }
    }
    
    /// A following session starts with the saved set on every client; a `--no-mutes` session with none.
    ///
    /// - Throws: ``CaptureStartError`` if a session couldn't start.
    func testSessionsStartWithTheSavedSet() throws {
        let following = try makeFollower(), bare = try makeFollower(following: false)
        let expected = calls(MuteList().changes(to: .testDefault))
        XCTAssertEqual(pathMutes(of: following, since: [0, 0, 0]), Array(repeating: expected, count: 3))
        XCTAssertEqual(pathMutes(of: bare, since: [0, 0, 0]), [[], [], []])
        XCTAssertEqual(following.session.appliedMutes, .testDefault)
    }
    
    /// An add reaches every client of every following session as one mute, and no other session.
    ///
    /// - Throws: ``CaptureStartError`` if a session couldn't start.
    func testAnAddReachesEveryFollowingClient() throws {
        let first = try makeFollower(), second = try makeFollower(), bare = try makeFollower(following: false)
        let starts = [first, second, bare].map { $0.factory.clients.map(\.calls.count) }
        XCTAssertEqual(send(.add, [MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")]), .ok)
        let mute = FakeEndpointSecurityClient.Call.setPathMute(
            PathMute(path: "/usr/bin/yes", type: ES_MUTE_PATH_TYPE_LITERAL), muted: true)
        XCTAssertEqual(pathMutes(of: first, since: starts[0]), [[mute], [mute], [mute]])
        XCTAssertEqual(pathMutes(of: second, since: starts[1]), [[mute], [mute], [mute]])
        XCTAssertEqual(pathMutes(of: bare, since: starts[2]), [[], [], []])
    }
    
    /// A remove reaches every following client as an unmute, live.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testARemoveReachesEveryFollowingClientAsAnUnmute() throws {
        let follower = try makeFollower()
        let start = follower.factory.clients.map(\.calls.count)
        XCTAssertEqual(send(.remove, [MuteFile.Entry(path: "/usr/libexec/logd", type: "ES_MUTE_PATH_TYPE_LITERAL")]),
                       .ok)
        let unmute = FakeEndpointSecurityClient.Call.setPathMute(
            PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL), muted: false)
        XCTAssertEqual(pathMutes(of: follower, since: start), [[unmute], [unmute], [unmute]])
    }
    
    /// A reset from a set of the user's sends exactly the difference back to the default set.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testAResetSendsOnlyTheDifference() throws {
        let follower = try makeFollower()
        let custom = [MuteFile.Entry(path: "/usr/libexec/logd", type: "ES_MUTE_PATH_TYPE_LITERAL"),
                      MuteFile.Entry(path: "/mine", type: "ES_MUTE_PATH_TYPE_PREFIX",
                                     events: ["ES_EVENT_TYPE_NOTIFY_EXEC"])]
        XCTAssertEqual(send(.replace, custom), .ok)
        let start = follower.factory.clients.map(\.calls.count)
        XCTAssertEqual(send(.reset), .ok)
        let customList = try MuteFile.list(from: custom, .strict).list
        let expected = calls(customList.changes(to: .testDefault))
        XCTAssertFalse(expected.contains { call in
            guard case .setPathMute(let mute, _) = call else { return false }
            return mute.path == "/usr/libexec/logd" && mute.type == ES_MUTE_PATH_TYPE_LITERAL
        }, "logd is muted for every event in both sets")
        XCTAssertEqual(pathMutes(of: follower, since: start), Array(repeating: expected, count: 3))
        XCTAssertEqual(follower.session.appliedMutes, .testDefault)
    }
    
    /// A session whose subscription is released gets no more changes; the others still do.
    ///
    /// - Throws: ``CaptureStartError`` if a session couldn't start.
    func testAReleasedSubscriptionGetsNothing() throws {
        let kept = try makeFollower()
        var released = try makeFollower()
        let starts = [kept, released].map { $0.factory.clients.map(\.calls.count) }
        released = Follower(session: released.session, factory: released.factory, subscription: nil)
        XCTAssertEqual(send(.add, [MuteFile.Entry(path: "/x", type: "ES_MUTE_PATH_TYPE_LITERAL")]), .ok)
        XCTAssertEqual(pathMutes(of: kept, since: starts[0]).map(\.count), [1, 1, 1])
        XCTAssertEqual(pathMutes(of: released, since: starts[1]), [[], [], []])
    }
    
    /// A refused or invalid change reaches no client.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testRefusedChangesReachNoClient() throws {
        let follower = try makeFollower()
        let start = follower.factory.clients.map(\.calls.count)
        XCTAssertEqual(send(.reset, access: .read), .refused)
        XCTAssertEqual(send(.replace, access: .read), .refused)
        XCTAssertEqual(send(.add, [MuteFile.Entry(path: "relative", type: "ES_MUTE_PATH_TYPE_LITERAL")]), .invalid)
        XCTAssertEqual(pathMutes(of: follower, since: start), [[], [], []])
    }
}
