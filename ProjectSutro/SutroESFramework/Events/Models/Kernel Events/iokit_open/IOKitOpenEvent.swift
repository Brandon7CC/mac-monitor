//
//  IOKitOpenEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_iokit_open_t
public struct IOKitOpenEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var user_client_type: Int64
    public var user_client_class: String
    
    /* fields available only if message version >= 10 */
    /// A `uint64_t`, kept by bit pattern. `nil` before message version 10, or in a record from Mac Monitor before
    /// 3.0.0, which left it out when the parent path was empty.
    public var parent_registry_id: Int64?
    public var parent_path: String?
    
    /* Mac Monitor enrichment, read from the IOKit registry at capture: IOKitRegistryService */
    /// The class of the service being opened: `IOSurfaceRoot`. `nil` before message version 10, when the service
    /// couldn't be read, or in a record from Mac Monitor before 3.1.0 or eslogger.
    public var parent_class: String?
    /// The bundle ID of the service's driver: its own `CFBundleIdentifier`, else its nearest provider's, unless a
    /// third-party kext defines its class (``IOKitDriverBundle``). `nil` as ``parent_class`` is, or when neither names
    /// one.
    public var driver_bundle_id: String?
    
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let ioKitEvent: es_event_iokit_open_t = rawMessage.pointee.event.iokit_open
        let version: Int = Int(rawMessage.pointee.version)
        
        self.user_client_class = ioKitEvent.user_client_class.string ?? ""
        self.user_client_type = Int64(ioKitEvent.user_client_type)
        /// A `uint64_t`, kept by bit pattern: one of 2^63 or more has no `Int64`.
        parent_registry_id = version >= 10 ? Int64(bitPattern: ioKitEvent.parent_registry_id) : nil
        parent_path = version >= 10 ? ioKitEvent.parent_path.string : nil

        /// Synchronous registry reads, with no file I/O, timed by `IOKitRegistryServicePerformanceTests`.
        let service = version >= 10
            ? IOKitRegistryService.read(path: parent_path, registryID: ioKitEvent.parent_registry_id) : nil
        parent_class = service?.className
        driver_bundle_id = service?.driverBundleID
    }
}
