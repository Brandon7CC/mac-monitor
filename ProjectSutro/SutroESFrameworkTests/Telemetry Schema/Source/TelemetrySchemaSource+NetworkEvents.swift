//
//  TelemetrySchemaSource+NetworkEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Network events
extension TelemetrySchemaSource {
    /// Mac Monitor's own network events: a flow that opened, and one that closed.
    static var networkEvents: [SchemaEvent] {
        let opened = "A network flow that opened, as the kernel's network statistics socket reported it."
        let closed = "A network flow that closed, with the kernel's byte totals."
        return [event(MacMonitorEvent.new_flow.type, opened, flowKeys),
                event(MacMonitorEvent.flow_closed.type, closed, flowKeys + byteKeys)]
    }

    /// The definitions only network records use, by their names in `$defs`.
    static var networkDefinitions: [String: SchemaObject] {
        [TelemetrySchema.networkDefinition: networkRecord, "flow_process": flowProcess, "flow_endpoint": flowEndpoint]
    }

    /// A network flow's record: Mac Monitor's own, with none of eslogger's envelope.
    static var networkRecord: SchemaObject {
        let shared = Dictionary(uniqueKeysWithValues: root.keys.map { ($0.name, $0) })
        let kept = [TelemetrySchema.versionKey, "indicators", "indicators_undetermined", "macOS", "sip_status",
                    "boot_session_uuid", "sensor_id"].compactMap { shared[$0] }
        return SchemaObject("A network flow's record, Mac Monitor's own: a record whose event key is "
                            + "\(TelemetrySchema.networkEventKeys.joined(separator: " or ")) follows this "
                            + "definition, not the schema's root. It has no version, schema_version, sequence "
                            + "numbers, thread, action, event_type or es_event_type, which mean Endpoint Security.",
                            kept + [
            enrichment("time", .pattern(.timespec), "When the flow was seen to connect, for new_flow, or to close, "
                        + "as eslogger writes a time: the kernel's time for the report it came from."),
            enrichment("mach_time", .integer, "The same time on Endpoint Security's clock (mach_absolute_time), so "
                        + "flows sort with Endpoint Security's events."),
            enrichment("process", .ref("flow_process"), "The socket's last user."),
            enrichment("event", .ref("event"), "The flow, under its event's key."),
            enrichment("context", .string, "A summary of the flow, as Mac Monitor's event list shows it: the URL, "
                        + "else the host and port, and for flow_closed the bytes in."),
            enrichment("target_path", .constant(MessageValues.notSupported), "A flow has no path."),
        ])
    }

    /// The keys both network events have.
    static var flowKeys: [SchemaKey] {
        let asked = "What the process asked for, from its own network parameters, not observed DNS."
        return [
            enrichment("identifier", .pattern(.uuid), "The flow's identifier: the same in its new_flow and its "
                        + "flow_closed while one capture reads the kernel's socket. Reading it again, after every "
                        + "stream and Mac Monitor stopped recording flows, makes new identifiers for flows open "
                        + "across it."),
            enrichment("remote_endpoint", .ref("flow_endpoint"), "The remote address and port. An IPv4-mapped IPv6 "
                        + "address is written as IPv4."),
            enrichment("remote_address_scope", .values(FlowAddressScope.allCases.map(\.rawValue)),
                       "Where the remote address is in the address space, from IANA's special-purpose address "
                        + "registries: public, private (RFC 1918 and IPv6 unique local), shared (100.64.0.0/10, for "
                        + "carrier-grade NAT), link_local, loopback, multicast, or reserved (documentation, "
                        + "benchmarking and other addresses never routed across the internet, and IPv6 outside "
                        + "2000::/3). An IPv4-mapped address, or one in NAT64's well-known prefix 64:ff9b::/96, has "
                        + "its IPv4 address's scope."),
            enrichment("local_endpoint", .ref("flow_endpoint"), "The local address and port.",
                       absent: Absence("the kernel gives none")),
            enrichment("remote_hostname", .string, "The name of the host the flow is to, with no trailing dot. For "
                        + "a Network.framework or NSURLSession connection, it's the host the process asked for. For "
                        + "a BSD socket, as curl and Python use, it's the name the process set on the socket, or else "
                        + "the name mDNSResponder last resolved the remote address to for the same program, which "
                        + "can come from an earlier run of it.",
                       absent: Absence("the process named none, and mDNSResponder resolved no name to the address "
                                       + "for it")),
            enrichment("url", .string, "A Network.framework connection's URL: its scheme, host and port, and its "
                        + "path unless Record URL paths is off. Never a user, password, query or fragment. A path "
                        + "segment shaped like a secret (a bot or webhook token, a JWT, 32 or more hex or mixed "
                        + "letters and digits) is <redacted>. At most \(FlowURL.limit) bytes. " + asked,
                       absent: Absence("the flow isn't a Network.framework TCP or QUIC connection that named one")),
            enrichment("first_party_site", .string, "The site the request was made for, as the process gave it. "
                        + asked, absent: Absence("the process named none")),
            enrichment("direction", .values(FlowDirection.allCases.map(\.rawValue)),
                       "Which side opened the flow, as the kernel says from macOS 14.",
                       absent: Absence("the kernel doesn't say, as on macOS 13 and for most UDP")),
            enrichment("socket_family", .integer, "The socket's address family: 2 (AF_INET) or 30 (AF_INET6)."),
            enrichment("socket_family_string", .string, "The name of `socket_family`."),
            enrichment("socket_type", .integer, "The socket's type: 1 (SOCK_STREAM) for TCP, 2 (SOCK_DGRAM) for UDP "
                        + "and QUIC."),
            enrichment("socket_type_string", .string, "The name of `socket_type`."),
            enrichment("socket_protocol", .integer, "The socket's protocol: 6 (IPPROTO_TCP) or 17 (IPPROTO_UDP)."),
            enrichment("socket_protocol_string", .string, "The name of `socket_protocol`."),
            enrichment("source_app", .ref("flow_process"), "The app a delegated socket acts for, such as the app "
                        + "that asked mDNSResponder for a lookup.", absent: Absence("the socket isn't delegated")),
            enrichment("start_time", .pattern(.timespec), "When the socket was made."),
        ]
    }

    /// The keys only a closed flow has.
    static var byteKeys: [SchemaKey] {
        let lost = Absence("the kernel's final counts were lost")
        return [enrichment("bytes_inbound_count", .integer, "The bytes the socket received in its life, as the "
                            + "kernel counts them. A flow open before the capture counts from before it.",
                           absent: lost),
                enrichment("bytes_outbound_count", .integer, "The bytes the socket sent in its life.", absent: lost)]
    }

    /// A flow's process: some of a process's keys, under the same names.
    static var flowProcess: SchemaObject {
        let unknown = Absence("neither a read of the running process nor Mac Monitor's lineage gave it")
        return SchemaObject("A network flow's process: some of a process's keys, under the same names. A key the "
                            + "socket and Mac Monitor's lineage didn't give is left out, never made up.", [
            enrichment("pid", .integer, "The process ID: 0 for the kernel."),
            enrichment("audit_token", .ref("audit_token"), "The process's audit token.", absent: unknown),
            enrichment("audit_token_string", .string, "`audit_token` as one line of text.", absent: unknown),
            enrichment("euid", .integer, "The effective user ID, from `audit_token`.", absent: unknown),
            enrichment("euid_human", .string, "The name of the effective user.",
                       absent: Absence("there's no `audit_token`, or the user has no name on the Mac that wrote "
                                       + "the record")),
            enrichment("ppid", .integer, "The parent's process ID.",
                       absent: Absence("the process was gone before its socket was first reported")),
            enrichment("group_id", .integer, "The process group.",
                       absent: Absence("the process was gone before its socket was first reported")),
            enrichment("session_id", .integer, "The session.",
                       absent: Absence("the process wasn't running when its socket was first reported")),
            enrichment("executable", .object(SchemaObject(nil, [
                enrichment("path", .string, "The executable's path."),
                enrichment("name", .string, "The last component of `path`."),
            ])), "The process's executable.", absent: unknown),
            enrichment("signing_id", .string, "The process's signing ID.",
                       absent: Absence("the code is unsigned, or its signature wasn't read")),
            enrichment("team_id", .string, "The process's team ID.",
                       absent: Absence("the code has none, or its signature wasn't read")),
            enrichment("codesigning_type", .values(CodeSigningType.allCases.filter { $0 != .unknown }.map(\.rawValue)),
                       "How the executable is signed.", absent: Absence("its signature wasn't read")),
        ])
    }

    /// An address and port.
    static var flowEndpoint: SchemaObject {
        SchemaObject("An address and port.", [
            enrichment("address", .string, "The address, as inet_ntop writes it, with no scope."),
            enrichment("port", .integer, "The port."),
        ])
    }
}
