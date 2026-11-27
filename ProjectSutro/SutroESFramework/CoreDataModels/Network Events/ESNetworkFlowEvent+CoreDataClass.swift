//
//  ESNetworkFlowEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//
//

import Foundation
import CoreData


/// A stored network flow, for both `new_flow` and `flow_closed` (``NetworkFlowEvent``).
@objc(ESNetworkFlowEvent)
public class ESNetworkFlowEvent: NSManagedObject, Identifiable {
    @NSManaged public var identifier: UUID?
    @NSManaged public var remote_address: String?
    @NSManaged public var remote_port: Int32
    @NSManaged public var remote_address_scope: String?
    @NSManaged public var local_address: String?
    @NSManaged public var local_port: NSNumber?
    @NSManaged public var remote_hostname: String?
    @NSManaged public var url: String?
    @NSManaged public var first_party_site: String?
    @NSManaged public var direction: String?

    @NSManaged public var socket_family: Int32
    @NSManaged public var socket_type: Int32
    @NSManaged public var socket_protocol: Int32
    @NSManaged public var socket_family_string: String?
    @NSManaged public var socket_type_string: String?
    @NSManaged public var socket_protocol_string: String?

    /// The app a delegated socket acts for, as ``FlowProcessRecord`` JSON.
    @NSManaged public var source_app: Data?
    @NSManaged public var start_time: String?
    @NSManaged public var bytes_inbound_count: NSNumber?
    @NSManaged public var bytes_outbound_count: NSNumber?

    /// The keys of the flow's event in its record.
    enum CodingKeys: CodingKey {
        case identifier, remote_endpoint, remote_address_scope, local_endpoint, remote_hostname, url
        case first_party_site, direction
        case socket_family, socket_family_string, socket_type, socket_type_string, socket_protocol
        case socket_protocol_string, source_app, start_time, bytes_inbound_count, bytes_outbound_count
    }

    /// The app a delegated socket acts for.
    public var sourceApp: FlowProcessRecord? {
        source_app.flatMap { try? JSONDecoder().decode(FlowProcessRecord.self, from: $0) }
    }

    /// - Parameters:
    ///   - event: The flow.
    ///   - message: Its message.
    ///   - context: The context to insert into.
    convenience init(from event: NetworkFlowEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        identifier = event.identifier
        (remote_address, remote_port) = (event.remote_endpoint.address, Int32(clamping: event.remote_endpoint.port))
        remote_address_scope = event.remote_address_scope?.rawValue
        local_address = event.local_endpoint?.address
        local_port = event.local_endpoint.map { NSNumber(value: $0.port) }
        (remote_hostname, url, first_party_site) = (event.remote_hostname, event.url, event.first_party_site)
        direction = event.direction?.rawValue
        (socket_family, socket_type, socket_protocol) = (event.socket_family, event.socket_type, event.socket_protocol)
        socket_family_string = event.socket_family_string
        socket_type_string = event.socket_type_string
        socket_protocol_string = event.socket_protocol_string
        source_app = event.source_app.flatMap { try? JSONEncoder().encode($0) }
        start_time = event.start_time
        bytes_inbound_count = event.bytes_inbound_count.map { NSNumber(value: $0) }
        bytes_outbound_count = event.bytes_outbound_count.map { NSNumber(value: $0) }
    }
}

// MARK: - Encodable conformance
extension ESNetworkFlowEvent: Encodable {
    /// Encode the flow as its record's event. An absent value's key is left out.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(identifier, forKey: .identifier)
        try container.encode(FlowEndpoint(address: remote_address ?? "", port: Int(remote_port)),
                             forKey: .remote_endpoint)
        try container.encodeIfPresent(remote_address_scope, forKey: .remote_address_scope)
        if let local_address, let local_port {
            try container.encode(FlowEndpoint(address: local_address, port: local_port.intValue),
                                 forKey: .local_endpoint)
        }
        try container.encodeIfPresent(remote_hostname, forKey: .remote_hostname)
        try container.encodeIfPresent(url, forKey: .url)
        try container.encodeIfPresent(first_party_site, forKey: .first_party_site)
        try container.encodeIfPresent(direction, forKey: .direction)
        try container.encode(socket_family, forKey: .socket_family)
        try container.encode(socket_family_string, forKey: .socket_family_string)
        try container.encode(socket_type, forKey: .socket_type)
        try container.encode(socket_type_string, forKey: .socket_type_string)
        try container.encode(socket_protocol, forKey: .socket_protocol)
        try container.encode(socket_protocol_string, forKey: .socket_protocol_string)
        try container.encodeIfPresent(sourceApp, forKey: .source_app)
        try container.encode(start_time, forKey: .start_time)
        try container.encodeIfPresent(bytes_inbound_count?.int64Value, forKey: .bytes_inbound_count)
        try container.encodeIfPresent(bytes_outbound_count?.int64Value, forKey: .bytes_outbound_count)
    }
}
