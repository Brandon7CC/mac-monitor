//
//  Recorded.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import os


// MARK: - Recorded values
/// Values a test collects from any thread, such as what a fake was asked or what a session emitted.
final class Recorded<Element> {
    private let lock = OSAllocatedUnfairLock<[Element]>(uncheckedState: [])

    /// Every value, in the order they came.
    var all: [Element] {
        lock.withLockUnchecked { $0 }
    }

    /// Keep a value.
    ///
    /// - Parameter element: The value.
    func append(_ element: Element) {
        lock.withLockUnchecked { $0.append(element) }
    }
}
