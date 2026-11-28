//
//  NetworkFlowFacts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A flow's facts
/// What Event Facts shows of a stored network flow, `new_flow` and `flow_closed` alike, a row at a time: which way it
/// went and its protocol, the remote host, the local endpoint, the URL, the first-party site, a closed flow's bytes
/// and how long it was open, the app a delegated socket acted for, and last the flow's identifier and when its socket
/// was made. A row whose value the flow doesn't have is left out. The process and its parent are in Message details,
/// as for any event.
public struct NetworkFlowFacts {
    /// The rows under the event's label, in order, each one's facts side by side.
    public let rows: [[EventFact]]

    /// Read a stored flow's facts, or `nil` for an event that isn't a network flow.
    ///
    /// - Parameter message: The event, on its context's queue.
    public init?(message: ESMessage) {
        let event = message.event
        guard message.isNetworkFlow, let flow = event.new_flow ?? event.flow_closed else { return nil }
        let opened = flow.start_time.flatMap { ESLogger.date(fromTime: $0, legacy: false) }
        let names = (flow.socket_protocol_string ?? "", flow.socket_family_string ?? "")
        var rows: [[EventFact?]] = [
            [flow.direction.nonEmpty.map { EventFact(name: "Direction", values: [$0]) },
             EventFact(name: "Protocol", values: Self.protocolPair(protocol: names.0, family: names.1))],
            [Self.remoteHost(of: flow)],
            [Self.localEndpoint(of: flow)],
            [flow.url.nonEmpty.map { EventFact(name: "URL", values: [$0], isLong: true) }],
            [Self.firstPartySite(of: flow)],
        ]
        if event.flow_closed != nil {
            let seconds = opened.flatMap { message.message_darwin_time?.timeIntervalSince($0) }
            rows.append([Self.count("Bytes in", flow.bytes_inbound_count),
                         Self.count("Bytes out", flow.bytes_outbound_count),
                         EventAge.text(seconds: seconds).map { EventFact(name: "Open for", values: [$0]) }])
        }
        rows.append([flow.sourceApp.map(Self.onBehalf(of:))])
        rows.append([flow.identifier.map { EventFact(name: "Flow ID", values: [$0.uuidString]) },
                     flow.start_time.map { EventFact(name: "Opened", values: [opened.map(eventLocalTime) ?? $0],
                                                     help: $0) }])
        self.rows = rows.map { $0.compactMap { $0 } }.filter { !$0.isEmpty }
    }
}


// MARK: - Values
extension NetworkFlowFacts {
    /// The address families Event Facts names by their IP version.
    private static let families = ["AF_INET": "IPv4", "AF_INET6": "IPv6"]

    /// A socket's protocol and address family, as Event Facts names them: `TCP` and `IPv4`. QUIC is UDP to the
    /// kernel.
    ///
    /// - Parameters:
    ///   - name: The protocol's name, as in `IPPROTO_TCP`.
    ///   - family: The family's name, as in `AF_INET6`.
    /// - Returns: The protocol without its `IPPROTO_` prefix, then the family's IP version, or each name as it is
    ///   when Event Facts doesn't shorten it.
    static func protocolPair(protocol name: String, family: String) -> [String] {
        [name.droppingPrefix("IPPROTO_"), families[family] ?? family]
    }

    /// The remote host: its hostname, when it has one other than its address, beside its address and port.
    ///
    /// - Parameter flow: The stored flow.
    /// - Returns: The fact.
    private static func remoteHost(of flow: ESNetworkFlowEvent) -> EventFact {
        let address = flow.remote_address ?? ""
        let endpoint = NetworkFlowEvent.hostAndPort(address, Int(flow.remote_port))
        guard let hostname = flow.remote_hostname.nonEmpty, hostname != address else {
            return EventFact(name: "Remote host", values: [endpoint])
        }
        return EventFact(name: "Remote host", values: [hostname, endpoint])
    }

    /// - Parameter flow: The stored flow.
    /// - Returns: Its local address and port, or `nil` when the kernel gave none.
    private static func localEndpoint(of flow: ESNetworkFlowEvent) -> EventFact? {
        guard let address = flow.local_address, let port = flow.local_port else { return nil }
        return EventFact(name: "Local endpoint", values: [NetworkFlowEvent.hostAndPort(address, port.intValue)])
    }

    /// The site the flow's request was made for, as a page's CDN and tracker requests name the page's site. A remote
    /// host that's the site, or a host in it, already shows it.
    ///
    /// - Parameter flow: The stored flow.
    /// - Returns: The fact, or `nil` when the flow has no site or its remote host is in it.
    private static func firstPartySite(of flow: ESNetworkFlowEvent) -> EventFact? {
        guard let site = flow.first_party_site.nonEmpty else { return nil }
        let host = flow.remote_hostname?.lowercased() ?? "", inSite = site.lowercased()
        guard host != inSite, !host.hasSuffix("." + inSite) else { return nil }
        return EventFact(name: "First-party site", values: [site])
    }

    /// A byte count as a whole number with a comma every three digits, as in `36,948`, whatever this Mac's locale.
    ///
    /// - Parameter bytes: The count.
    /// - Returns: The count.
    static func count(_ bytes: Int64) -> String {
        bytes.formatted(.number.locale(Locale(identifier: "en_US")))
    }

    /// A closed flow's byte total, with its size in decimal units on hover from a thousand bytes on.
    ///
    /// - Parameters:
    ///   - name: The fact's name.
    ///   - bytes: The total, or `nil` when the final counts were lost.
    /// - Returns: The fact, or `nil` without a total.
    private static func count(_ name: String, _ bytes: NSNumber?) -> EventFact? {
        guard let bytes = bytes?.int64Value else { return nil }
        return EventFact(name: name, values: [count(bytes)],
                         help: bytes < 1_000 ? nil : NetworkFlowEvent.byteCount(bytes))
    }

    /// The app a delegated socket acts for: its executable's name beside its signing ID, either alone when the other
    /// isn't known or is the same, or its pid when neither is known. Its path shows on hover.
    ///
    /// - Parameter app: The app.
    /// - Returns: The fact.
    private static func onBehalf(of app: FlowProcessRecord) -> EventFact {
        let name = (app.executable?.name).nonEmpty, signingID = app.signing_id.nonEmpty
        let names = [name, signingID == name ? nil : signingID].compactMap { $0 }
        return EventFact(name: "On behalf of", values: names.isEmpty ? ["PID \(app.pid)"] : names,
                         help: app.executable?.path)
    }
}
