//
//  FakeLaunchServicesReaders.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation
import os
@testable import SutroESFramework


// MARK: - A scripted LaunchServices
/// A LaunchServices reader with scripted records, which remembers the pids it was asked about.
final class FakeLaunchServicesReader: LaunchServicesReading {
    /// The record for a pid, given how many times it was asked about before.
    private let records: (pid_t, Int) -> LaunchServicesRecord?
    /// The pids asked about, in order.
    private let asked = OSAllocatedUnfairLock(uncheckedState: [pid_t]())

    /// - Parameter records: The record for a pid, given how many times it was asked about before. By default none.
    init(_ records: @escaping (pid_t, Int) -> LaunchServicesRecord? = { _, _ in nil }) {
        self.records = records
    }

    /// The scripted record.
    ///
    /// - Parameter pid: The pid.
    /// - Returns: The record, or `nil`.
    func record(forPID pid: pid_t) -> LaunchServicesRecord? {
        let attempt = asked.withLockUnchecked { asked in
            asked.append(pid)
            return asked.filter { $0 == pid }.count - 1
        }
        return records(pid, attempt)
    }

    /// The pids asked about, in order.
    var askedPIDs: [pid_t] {
        asked.withLockUnchecked { $0 }
    }
}


// MARK: - A reader that waits
/// A Launch Services reader whose reads wait until the test lets them through, then find nothing.
final class WaitingLaunchServicesReader: LaunchServicesReading {
    private let gate = DispatchSemaphore(value: 0)
    
    /// Let every read waiting now, and every read after, through.
    func open() {
        for _ in 0..<64 { gate.signal() }
    }
    
    /// Wait for ``open()``.
    ///
    /// - Parameter pid: The pid.
    /// - Returns: `nil`.
    func record(forPID pid: pid_t) -> LaunchServicesRecord? {
        gate.wait()
        gate.signal()
        return nil
    }
}
