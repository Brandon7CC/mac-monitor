//
//  SensorClientTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Signals
/// Pins where `SensorClient` delivers its signals. `EndpointSecurityManager` keeps its pending signals on the main
/// thread, so a signal from the connection's queue would race it.
final class SensorClientTests: XCTestCase {
    /// An agent that takes every batch.
    private final class SilentAgent: NSObject, AgentProtocol {
        func receive(events: [Data], reply: @escaping () -> Void) { reply() }
    }

    /// An interruption fired off the main thread reaches `onSignal` on the main thread.
    func testAnInterruptionSignalsOnTheMainThread() {
        let signaled = expectation(description: "restarted")
        let onMain = Recorded<Bool>()
        let client = SensorClient(agent: SilentAgent()) { signal in
            guard signal == .restarted else { return }
            onMain.append(Thread.isMainThread)
            signaled.fulfill()
        }
        let listener = NSXPCListener.anonymous()
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        client.configure(connection)
        connection.activate()
        defer { connection.invalidate() }

        DispatchQueue.global().async { connection.interruptionHandler?() }
        wait(for: [signaled], timeout: 5)
        XCTAssertEqual(onMain.all, [true])
    }
}
