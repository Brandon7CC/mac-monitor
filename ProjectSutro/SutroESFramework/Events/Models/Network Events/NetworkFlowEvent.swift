//
//  NetworkFlowEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Network flow events
/// A network flow that opened (`new_flow`) or closed (`flow_closed`), as the kernel's network statistics socket
/// reported it. Mac Monitor's own event: no Endpoint Security message makes it. The keys follow Apple's
/// `NEFilterSocketFlow` and `NEFilterReport`.
///
/// The URL and first-party site are what the process asked for, not observed DNS. So is the hostname of a
/// Network.framework connection. A BSD socket's is the name mDNSResponder last resolved its remote address to for
/// the same program, unless the process set one. A closed flow carries the kernel's byte totals when its final counts
/// came.
public struct NetworkFlowEvent: Codable, IdentityHashable {
    public var id = UUID.buffered()

    /// Made when the flow opened, or was adopted: the same in its `new_flow` and its `flow_closed`.
    public var identifier: UUID
    public var remote_endpoint: FlowEndpoint
    /// Where the remote address is in the address space, as public or private.
    public var remote_address_scope: FlowAddressScope?
    public var local_endpoint: FlowEndpoint?
    public var remote_hostname: String?
    /// A Network.framework connection's URL: no query or fragment, and its path only while URL paths are recorded.
    public var url: String?
    public var first_party_site: String?
    public var direction: FlowDirection?

    /// `AF_INET` or `AF_INET6`, `SOCK_STREAM` or `SOCK_DGRAM`, and `IPPROTO_TCP` or `IPPROTO_UDP`.
    public var socket_family, socket_type, socket_protocol: Int32
    public var socket_family_string = "", socket_type_string = "", socket_protocol_string = ""

    /// The app a delegated socket acts for.
    public var source_app: FlowProcessRecord?
    /// When the socket was made, as eslogger writes a time.
    public var start_time: String
    /// The kernel's byte totals, for a closed flow whose final counts came.
    public var bytes_inbound_count, bytes_outbound_count: Int64?

    /// The subscription that keeps a URL's path, which Settings and `macmonitor stream` turn off.
    public static let urlPathsSubscriptionName = "url_paths"

    /// - Parameters:
    ///   - record: The flow, as the client handed it over.
    ///   - keepingURLPath: Keep the URL's path? Without it the URL ends at the host and port.
    init(_ record: FlowRecord, keepingURLPath: Bool) {
        identifier = record.identifier
        remote_endpoint = record.remote
        local_endpoint = record.local
        remote_hostname = record.hostname
        url = keepingURLPath ? record.url : record.url.flatMap { FlowURL.sanitized($0, keepingPath: false) }
        first_party_site = record.firstPartySite
        direction = record.direction
        (socket_family, socket_type, socket_protocol) = (record.family, record.type, record.proto)
        source_app = record.sourceApp.map(FlowProcessRecord.init)
        start_time = ESLogger.time(nanoseconds: record.start)
        if record.kind == .closed {
            bytes_inbound_count = record.bytesIn.map { Int64(clamping: $0) }
            bytes_outbound_count = record.bytesOut.map { Int64(clamping: $0) }
        }
        enrich()
    }

    /// What the event tables show: the URL when there is one, else the host and port. A closed flow adds its bytes
    /// in, as in `en.wikipedia.org:443 · 36.4 KB in`.
    ///
    /// - Parameter closed: Is it the flow's close?
    /// - Returns: The context.
    func summary(closed: Bool) -> String {
        let place = url ?? Self.hostAndPort(remote_hostname ?? remote_endpoint.address, remote_endpoint.port)
        guard closed, let bytes = bytes_inbound_count else { return place }
        return place + " · " + Self.byteCount(bytes) + " in"
    }

    /// A host and port as a URL writes them. An IPv6 literal is bracketed. A DNS name has no colon.
    ///
    /// - Parameters:
    ///   - host: An address or a hostname.
    ///   - port: The port.
    /// - Returns: The two, as in `en.wikipedia.org:443` or `[2001:db8::1]:443`.
    static func hostAndPort(_ host: String, _ port: Int) -> String {
        (host.contains(":") ? "[\(host)]" : host) + ":\(port)"
    }

    /// A byte count in decimal units (1,000) with one fraction digit, as in `36.4 KB`. The same on every Mac, whatever
    /// its locale.
    ///
    /// - Parameter bytes: The count.
    /// - Returns: The count, as in `512 bytes` or `1.2 MB`.
    static func byteCount(_ bytes: Int64) -> String {
        guard bytes >= 1_000 else { return bytes == 1 ? "1 byte" : "\(bytes) bytes" }
        let units = ["KB", "MB", "GB", "TB", "PB"]
        var value = Double(bytes) / 1_000, unit = 0
        while value >= 999.95, unit < units.count - 1 {
            value /= 1_000
            unit += 1
        }
        return String(format: "%.1f", value) + " " + units[unit]
    }
}


// MARK: - Mac Monitor enrichment
extension NetworkFlowEvent: ESEnrichable {
    /// Derive the remote address's scope, and the names of the socket's family, type and protocol.
    public mutating func enrich() {
        remote_address_scope = FlowAddressScope(address: remote_endpoint.address)
        socket_family_string = resolve(domain: socket_family)
        socket_type_string = resolve(type: socket_type)
        socket_protocol_string = resolve(protocol: socket_protocol)
    }
}
