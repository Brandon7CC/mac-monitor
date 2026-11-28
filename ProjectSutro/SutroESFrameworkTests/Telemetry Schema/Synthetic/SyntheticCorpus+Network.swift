//
//  SyntheticCorpus+Network.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Network records
extension SyntheticCorpus {
    /// The network events' records, made from flow records as a session makes them (`Message(flow:)`), not by the
    /// synthetic decoder: a flow's message has only what the socket gives. Each variant leaves out what the kernel
    /// or the lineage table may not give, so every optional key of the network definitions is seen both ways. The
    /// minimal one also has no SIP status or boot session, as when neither could be read.
    ///
    /// - Returns: The records, `new_flow`'s then `flow_closed`'s.
    static func networkRecords() -> [Record] {
        let delegate = SyntheticFlows.process(pid: 249, path: "/usr/sbin/mDNSResponder",
                                              signingID: "com.apple.mDNSResponder")
        let variants: [(name: String, make: (FlowRecord.Kind) -> Message)] = [
            ("full", { SyntheticFlows.message(SyntheticFlows.record($0)) }),
            ("delegated", {
                SyntheticFlows.message(SyntheticFlows.record($0, process: delegate,
                                                             sourceApp: SyntheticFlows.process()))
            }),
            ("minimal", {
                SyntheticFlows.message(SyntheticFlows.record($0, minimal: true), sipStatus: nil, bootSession: nil)
            }),
            ("zombie", {
                SyntheticFlows.message(SyntheticFlows.record($0, process: SyntheticFlows.process(state: .zombie)))
            }),
            ("unresolved process", {
                SyntheticFlows.message(SyntheticFlows.record($0, process: SyntheticFlows.process(state: .reaped)))
            }),
        ]
        let closedOnly: [(name: String, make: (FlowRecord.Kind) -> Message)] = [
            ("lost counts", { SyntheticFlows.message(SyntheticFlows.record($0, counted: false)) }),
        ]
        return [(MacMonitorEvent.new_flow, FlowRecord.Kind.opened), (.flow_closed, .closed)].flatMap { event, kind in
            (variants + (kind == .closed ? closedOnly : [])).map { variant in
                Record(label: "\(event.name) (\(variant.name))",
                       variant: SyntheticVariant(name: variant.name, full: false), message: variant.make(kind))
            }
        }
    }
}
