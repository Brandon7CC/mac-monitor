//
//  TargetProcessNameTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The name of an event's process
/// Pins the name Event Facts' process button and process tree give an event's process: an exec's target, a fork's
/// child, any other event's process, and a network flow's process by its pid when its executable wasn't read, the
/// kernel's as `kernel_task`.
final class TargetProcessNameTests: XCTestCase {
    /// - Parameter message: An event.
    /// - Returns: Its process's name, read from the stored event.
    private func name(_ message: Message) -> String {
        withStoredEvent(message) { ProcessHelpers.getTargetProcessName(message: $0) }
    }

    /// An exec names its target, a fork its child, and an exit its process.
    func testEndpointSecurityEvents() throws {
        let login = try esloggerProcess(pid: 401, pidversion: 4009, path: "/usr/bin/login", parent: (300, 3000))
        let child = try esloggerProcess(pid: 402, pidversion: 4020, path: "/bin/sh", parent: (401, 4009))
        XCTAssertEqual(name(try execMessage(by: login, of: try shell())), "zsh")
        XCTAssertEqual(name(try forkMessage(by: login, of: child)), "sh")
        XCTAssertEqual(name(try exitMessage(of: login)), "login")
    }

    /// An exec is named by its target alone. The process tree names every ancestor this way, so the event's own
    /// process stays unloaded.
    func testExecLeavesItsProcessUnloaded() throws {
        let login = try esloggerProcess(pid: 401, pidversion: 4009, path: "/usr/bin/login", parent: (300, 3000))
        try withEventStore([try execMessage(by: login, of: try shell())]) { context, _ in
            context.reset()
            let exec = try XCTUnwrap(context.fetch(ESMessage.request()).first)
            XCTAssertEqual(ProcessHelpers.getTargetProcessName(message: exec), "zsh")
            XCTAssertTrue(exec.process.isFault, "Naming an exec loaded its event's process")
        }
    }

    /// A flow names its process's executable. A process reaped before it was read has none, so it's named by its pid.
    func testNetworkFlows() {
        XCTAssertEqual(name(SyntheticFlows.message(SyntheticFlows.record(.opened))), "nscurl")
        let reaped = SyntheticFlows.record(.closed, process: SyntheticFlows.process(pid: 4_390, state: .reaped))
        XCTAssertEqual(name(SyntheticFlows.message(reaped)), "PID 4390")
    }

    /// pid 0 without an executable is the kernel, named `kernel_task` as `ps` names it.
    func testTheKernel() {
        let kernel = SyntheticFlows.record(.opened, process: SyntheticFlows.process(pid: 0, state: .reaped))
        XCTAssertEqual(name(SyntheticFlows.message(kernel)), "kernel_task")
    }
}
