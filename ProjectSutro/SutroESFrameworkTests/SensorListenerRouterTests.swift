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
    /// A connection that records what was done to it, in order.
    private final class FakePeer: PeerConnection {
        let effectiveUserIdentifier: uid_t
        /// What happened: "requirement <...>", then the endpoint that took it.
        var log: [String] = []
        
        /// - Parameter euid: The peer's effective user ID.
        init(euid: uid_t) {
            effectiveUserIdentifier = euid
        }
        
        /// Record the requirement.
        ///
        /// - Parameter requirement: The requirement string.
        func setCodeSigningRequirement(_ requirement: String) {
            log.append("requirement \(requirement)")
        }
    }
    
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
