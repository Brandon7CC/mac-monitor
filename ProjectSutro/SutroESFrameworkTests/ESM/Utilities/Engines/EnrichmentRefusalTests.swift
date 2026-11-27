//
//  EnrichmentRefusalTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Why an enrichment switch was refused
/// Pins what Settings > General's enrichment switches say when the Security Extension refuses a change, on or off,
/// by Mac Monitor's handshake. Only a Mac Monitor whose capture runs was refused for the switch's own reason, such as
/// the kernel's network statistics, and only when the Security Extension answered.
final class EnrichmentRefusalTests: XCTestCase {
    /// The reason Record network flows and Record URL paths give while capture runs.
    let flows = "Network flows can't be read on this Mac."
    /// What every switch says when capture isn't running.
    let notRunning = "Mac Monitor can't record yet, so nothing changed."

    /// Capture runs for this Mac Monitor, so the switch's own reason stopped it.
    func testCaptureRunning() {
        XCTAssertEqual(NewClientResult.success.refusal(answered: true, onThisMac: flows), flows)
    }

    /// A switch with no reason of its own while capture runs, as scanning, was refused while capture stopped.
    func testCaptureRunningWithoutAReason() {
        XCTAssertEqual(NewClientResult.success.refusal(answered: true, onThisMac: nil), notRunning)
    }

    /// Another Mac Monitor owns the event stream, worded as Settings > Command Line words it.
    func testStreamOwned() {
        for reason in [flows, nil] {
            XCTAssertEqual(NewClientResult.streamOwned.refusal(answered: true, onThisMac: reason),
                           "Another Mac Monitor owns the event stream, so only it can change this.")
        }
        XCTAssertEqual(CommandLineAccessChange.streamOwned.message,
                       "Another Mac Monitor owns the event stream, so only it can change this. Nothing changed.")
    }

    /// Capture isn't running: no handshake yet, or Endpoint Security refused it.
    func testCaptureNotRunning() {
        for result in [NewClientResult.waiting, .notPermitted, .tooManyClients, .notEntitled, .notPrivileged,
                       .internalSubsystem, .invalidArgument] {
            XCTAssertEqual(result.refusal(answered: true, onThisMac: flows), notRunning, "\(result.rawValue)")
        }
    }

    /// No answer: the Security Extension isn't running, whatever the last handshake said, as after it's uninstalled.
    func testNoAnswer() {
        for result in [NewClientResult.success, .streamOwned, .waiting] {
            XCTAssertEqual(result.refusal(answered: false, onThisMac: flows), notRunning, "\(result.rawValue)")
        }
    }
}
