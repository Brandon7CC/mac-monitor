//
//  FlowCollector.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - A consumer of flows
/// Keeps every record the network statistics client hands it.
final class FlowCollector: FlowConsumer {
    let records = Recorded<FlowRecord>()

    /// - Parameter record: A record.
    func handle(_ record: FlowRecord) {
        records.append(record)
    }
}
