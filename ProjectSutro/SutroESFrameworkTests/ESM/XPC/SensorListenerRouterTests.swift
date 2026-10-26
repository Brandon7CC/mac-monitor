//
//  SensorListenerRouterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Routing connections
/// Pins the Security Extension's security-critical routing: root's connections only ever reach `macmonitor`'s
/// endpoint and everyone else's only Mac Monitor's, each pinned to that program's code signing requirement before its
/// endpoint sees it.
final class SensorListenerRouterTests: XCTestCase {
    /// A router whose endpoints record which one took each connection.
    private let router = SensorListenerRouter<FakePeer>(app: { $0.log.append("app") },
                                                       commandLine: { $0.log.append("commandLine") })
    
    /// Root is `macmonitor`: pinned to its requirement, then handed to its endpoint, never Mac Monitor's.
    func testRootIsTheCommandLineTool() {
        let peer = FakePeer(euid: 0)
        XCTAssertEqual(router.route(peer), .commandLine)
        XCTAssertEqual(peer.log, ["requirement \(SensorXPC.commandLineRequirement)", "commandLine"])
    }
    
    /// Anyone else is Mac Monitor: pinned to its requirement, then handed to its endpoint, never `macmonitor`'s.
    func testEveryoneElseIsMacMonitor() {
        for euid: uid_t in [501, 502, 1, 4_294_967_294] {
            let peer = FakePeer(euid: euid)
            XCTAssertEqual(router.route(peer), .app)
            XCTAssertEqual(peer.log, ["requirement \(SensorXPC.agentRequirement)", "app"], "euid \(euid)")
        }
    }
    
    /// The two roles' requirements are different programs.
    func testTheRolesPinDifferentPrograms() {
        XCTAssertNotEqual(SensorListenerRouter<FakePeer>.Role.app.requirement,
                          SensorListenerRouter<FakePeer>.Role.commandLine.requirement)
        XCTAssertEqual(SensorListenerRouter<FakePeer>.role(forEffectiveUser: 0), .commandLine)
        XCTAssertEqual(SensorListenerRouter<FakePeer>.role(forEffectiveUser: 501), .app)
    }
    
    /// A connection a listener accepts carries the peer's effective user: this test process isn't root, so its
    /// connection is Mac Monitor's.
    func testAnAcceptedConnectionRoutesByItsPeer() throws {
        try XCTSkipIf(geteuid() == 0, "The test process is root.")
        let delegate = RoutingDelegate(accepted: expectation(description: "accepted"))
        let listener = NSXPCListener.anonymous()
        listener.delegate = delegate
        listener.activate()
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = SensorXPC.sensorInterface
        connection.activate()
        defer { connection.invalidate() }
        (connection.remoteObjectProxyWithErrorHandler { _ in } as? SensorProtocol)?.eventSubscriptions { _ in }
        wait(for: [delegate.accepted], timeout: 5)
        XCTAssertEqual(delegate.roles, [.app])
    }
}


// MARK: - The pin, enforced
/// A one-call interface for checking the router's pin on a real connection.
@objc private protocol Ping {
    /// Answer.
    ///
    /// - Parameter reply: Called with `true`.
    func ping(reply: @escaping (Bool) -> Void)
}


/// Answers pings and counts them.
private final class Pinger: NSObject, Ping, NSXPCListenerDelegate {
    private var router: SensorListenerRouter<NSXPCConnection>?
    private let calls = NSLock()
    private var count = 0
    
    /// How many pings reached the endpoint.
    var pings: Int { calls.withLock { count } }
    
    /// - Parameter routes: Route each connection through ``SensorListenerRouter``, or serve it unpinned.
    init(routes: Bool) {
        super.init()
        guard routes else { return }
        router = SensorListenerRouter<NSXPCConnection>(app: { [weak self] in self?.serve($0) },
                                                       commandLine: { [weak self] in self?.serve($0) })
    }
    
    /// Answer pings on a connection.
    ///
    /// - Parameter connection: The connection.
    private func serve(_ connection: NSXPCConnection) {
        connection.exportedInterface = NSXPCInterface(with: Ping.self)
        connection.exportedObject = self
        connection.activate()
    }
    
    /// - Parameter reply: Called with `true`.
    func ping(reply: @escaping (Bool) -> Void) {
        calls.withLock { count += 1 }
        reply(true)
    }
    
    /// Route the connection, as the Security Extension's listener does.
    ///
    /// - Parameters:
    ///   - listener: The listener.
    ///   - newConnection: The connection.
    /// - Returns: `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        if let router { _ = router.route(newConnection) } else { serve(newConnection) }
        return true
    }
}


extension SensorListenerRouterTests {
    /// Ping an endpoint once.
    ///
    /// - Parameter pinger: The endpoint.
    /// - Returns: `true` if it answered, `false` if the connection failed.
    private func ping(_ pinger: Pinger) -> Bool {
        let listener = NSXPCListener.anonymous()
        listener.delegate = pinger
        listener.activate()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: Ping.self)
        connection.activate()
        defer { connection.invalidate() }
        
        let answered: Bool? = try? awaitCallback(timeout: 5) { done in
            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done(false) } as? Ping
            proxy?.ping { _ in done(true) }
        }
        return answered ?? false
    }
    
    /// The router's pin is enforced, not just set: this test process isn't signed as Mac Monitor, so its message
    /// never reaches the endpoint. The same endpoint without the router answers it.
    func testAnUnsignedCallerNeverReachesTheEndpoint() {
        let unpinned = Pinger(routes: false)
        XCTAssertTrue(ping(unpinned), "Without the router the endpoint answers")
        let routed = Pinger(routes: true)
        XCTAssertFalse(ping(routed))
        XCTAssertEqual(routed.pings, 0)
    }
}


// MARK: - A listener that routes
/// Routes each connection its listener accepts, records the role, and drops the connection.
private final class RoutingDelegate: NSObject, NSXPCListenerDelegate {
    let accepted: XCTestExpectation
    /// The roles routed, in order.
    private(set) var roles: [SensorListenerRouter<NSXPCConnection>.Role] = []
    private let router = SensorListenerRouter<NSXPCConnection>(app: { $0.invalidate() },
                                                               commandLine: { $0.invalidate() })
    
    /// - Parameter accepted: Fulfilled once a connection is routed.
    init(accepted: XCTestExpectation) {
        self.accepted = accepted
    }
    
    /// Route the connection.
    ///
    /// - Parameters:
    ///   - listener: The listener.
    ///   - connection: The incoming connection.
    /// - Returns: `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        roles.append(router.route(connection))
        accepted.fulfill()
        return true
    }
}
