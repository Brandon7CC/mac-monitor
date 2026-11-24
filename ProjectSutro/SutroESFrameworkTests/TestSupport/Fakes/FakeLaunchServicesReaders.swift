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
/// A Launch Services reader whose reads wait until the test lets them through, then give the scripted record.
///
/// The upgrader reads on one serial queue, so a read that waits holds every lookup behind it.
final class WaitingLaunchServicesReader: LaunchServicesReading {
    /// Signalled once for each read let through
    private let gate = DispatchSemaphore(value: 0)
    private let isOpen = OSAllocatedUnfairLock(initialState: false)
    /// What ``answer(then:)`` asked to run, oldest first, one for each read let through
    private let answered = OSAllocatedUnfairLock(uncheckedState: [(pid_t) -> Void]())
    /// Gives the records and remembers the pids asked about
    private let scripted: FakeLaunchServicesReader

    /// - Parameter records: The record for a pid, given how many reads of it went through before. By default none.
    init(_ records: @escaping (pid_t, Int) -> LaunchServicesRecord? = { _, _ in nil }) {
        scripted = FakeLaunchServicesReader(records)
    }

    /// Let one read through.
    ///
    /// `then` runs on the upgrader's queue as the read returns its record. The lookup's completion runs right after
    /// on that queue, so `queue.sync {}` on it once `then` has run waits for the completion too.
    ///
    /// - Parameter then: Gets the pid that was read.
    func answer(then: @escaping (pid_t) -> Void) {
        answered.withLockUnchecked { $0.append(then) }
        gate.signal()
    }

    /// Let every read waiting now, and every read after, through.
    func open() {
        isOpen.withLock { $0 = true }
        gate.signal()
    }

    /// Wait for ``answer(then:)`` or ``open()``, then give the scripted record.
    ///
    /// - Parameter pid: The pid.
    /// - Returns: The record, or `nil`.
    func record(forPID pid: pid_t) -> LaunchServicesRecord? {
        gate.wait()
        // Once open, each read passes the gate on to the next.
        if isOpen.withLock({ $0 }) { gate.signal() }
        let record = scripted.record(forPID: pid)
        let then = answered.withLockUnchecked { $0.isEmpty ? nil : $0.removeFirst() }
        then?(pid)
        return record
    }

    /// The pids whose reads went through, in order.
    var askedPIDs: [pid_t] {
        scripted.askedPIDs
    }
}
