//
//  XCTestCase+FIFO.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
import os


// MARK: - Named pipes
extension XCTestCase {
    /// A named pipe in a fresh folder, with no writer, so opening it to read blocks unless the open doesn't wait.
    ///
    /// - Parameter name: The pipe's file name.
    /// - Returns: The pipe's path.
    /// - Throws: The error making the folder, or a `POSIXError` from `mkfifo`.
    func makeFIFO(named name: String = "fifo") throws -> String {
        let fifo = try makeTemporaryDirectory().appendingPathComponent(name).path
        guard mkfifo(fifo, 0o600) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return fifo
    }
    
    /// Run something that mustn't block on a named pipe, on another queue, and wait for it at most `timeout`.
    ///
    /// One that blocks fails the test. It's then let go by opening the pipe for writing, so no thread stays stuck in
    /// `open` for the rest of the run.
    ///
    /// - Parameters:
    ///   - fifo: The pipe it might block on.
    ///   - timeout: How long to wait, in seconds.
    ///   - body: The work, such as reading the pipe.
    /// - Returns: What `body` returned or threw.
    /// - Throws: An `XCTest` failure if `body` didn't return in time.
    func withoutBlocking<T>(on fifo: String, timeout: TimeInterval = 2,
                            _ body: @escaping () throws -> T) throws -> Result<T, Error> {
        let result = OSAllocatedUnfairLock<Result<T, Error>?>(uncheckedState: nil)
        let returned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let outcome = Result(catching: body)
            result.withLockUnchecked { $0 = outcome }
            returned.signal()
        }
        if returned.wait(timeout: .now() + timeout) == .timedOut {
            XCTFail("Blocked on \(fifo) for \(timeout) seconds.")
            let writer = open(fifo, O_WRONLY | O_NONBLOCK)
            /// The reader's open returns once a writer is there, so keep this end open until it has.
            _ = returned.wait(timeout: .now() + 5)
            if writer >= 0 { close(writer) }
        }
        return try XCTUnwrap(result.withLockUnchecked { $0 })
    }
}
