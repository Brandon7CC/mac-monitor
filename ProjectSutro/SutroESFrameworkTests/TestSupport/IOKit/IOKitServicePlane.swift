//
//  IOKitServicePlane.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import IOKit


// MARK: - This Mac's services
/// A service in this Mac's IOKit registry, as an IOKit open names one: its service-plane path and registry ID, with
/// the class it had when it was listed.
struct IOKitServicePlaneEntry {
    /// Its service-plane path, from `IORegistryEntryGetPath`.
    let path: String
    /// Its registry ID, which the kernel never reuses.
    let registryID: UInt64
    /// Its class, from `IOObjectGetClass`.
    let className: String
}

/// Lists the services in this Mac's IOKit registry, for tests and benchmarks that read every one.
enum IOKitServicePlane {
    /// Every entry in the service plane that isn't a user client, as the parent of an IOKit open is the service a
    /// user client connects to. An entry whose path is longer than `io_string_t` holds is left out.
    ///
    /// - Returns: The entries, in the registry's order. Empty when the registry can't be walked.
    static func services() -> [IOKitServicePlaneEntry] {
        var iterator: io_iterator_t = IO_OBJECT_NULL
        guard IORegistryCreateIterator(kIOMainPortDefault, kIOServicePlane, IOOptionBits(kIORegistryIterateRecursively),
                                       &iterator) == KERN_SUCCESS else { return [] }
        defer { IOObjectRelease(iterator) }
        var services: [IOKitServicePlaneEntry] = []
        var entry = IOIteratorNext(iterator)
        while entry != IO_OBJECT_NULL {
            if let service = service(entry) { services.append(service) }
            IOObjectRelease(entry)
            entry = IOIteratorNext(iterator)
        }
        return services
    }

    /// - Parameter entry: A registry entry.
    /// - Returns: The entry as a service, or `nil` for a user client or one whose path, ID or class can't be read.
    private static func service(_ entry: io_registry_entry_t) -> IOKitServicePlaneEntry? {
        guard IOObjectConformsTo(entry, "IOUserClient") == 0 else { return nil }
        var path = [CChar](repeating: 0, count: MemoryLayout<io_string_t>.size)
        var name = [CChar](repeating: 0, count: MemoryLayout<io_name_t>.size)
        var id: UInt64 = 0
        guard IORegistryEntryGetPath(entry, kIOServicePlane, &path) == KERN_SUCCESS,
              IORegistryEntryGetRegistryEntryID(entry, &id) == KERN_SUCCESS,
              IOObjectGetClass(entry, &name) == KERN_SUCCESS else { return nil }
        return IOKitServicePlaneEntry(path: String(cString: path), registryID: id, className: String(cString: name))
    }

    /// - Parameter path: A registry path.
    /// - Returns: The registry ID of the entry `IORegistryEntryFromPath` finds for it, or `nil` for none.
    static func registryID(resolving path: String) -> UInt64? {
        let entry = IORegistryEntryFromPath(kIOMainPortDefault, path)
        guard entry != IO_OBJECT_NULL else { return nil }
        defer { IOObjectRelease(entry) }
        var id: UInt64 = 0
        return IORegistryEntryGetRegistryEntryID(entry, &id) == KERN_SUCCESS ? id : nil
    }
}
