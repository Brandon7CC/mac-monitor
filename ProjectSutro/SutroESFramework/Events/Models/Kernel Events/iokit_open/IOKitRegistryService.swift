//
//  IOKitRegistryService.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import IOKit


// MARK: - The service an IOKit open connects to
/// What the IOKit registry says about the service an `iokit_open` connects to: its class and its driver's bundle ID
/// (``IOKitDriverBundle``). The Security Extension reads it when it captures the event. Opening a trace never reads it.
///
/// The service is found by the event's `parent_path`, checked against its `parent_registry_id`. A registry path isn't
/// unique: siblings can share a name and have no location, and `IORegistryEntryFromPath` returns the first that
/// matches, so a path can name a sibling of the service that was opened. A registry ID is never reused, so when the
/// entry the path finds has another ID, or the path finds none, the service is looked up by its ID instead. An entry
/// that was never registered for matching, such as a daemon's IOTimeSync client, can't be found by its ID, so it then
/// reads as nothing rather than as a sibling.
///
/// Each read is synchronous registry calls into the kernel, with no file or network I/O. On a MacBook Pro (Mac17,3)
/// on macOS 27.2, two runs of `IOKitRegistryServicePerformanceTests` measured these median wall times per read:
/// - IOSurfaceRoot by path and ID, about 10 to 14 µs (`capture.iokit.registry.path`).
/// - Every service by path and ID, about 19 to 21 µs averaged, the ID lookups after an ambiguous path included
///   (`capture.iokit.registry.path.all`).
/// - A path the registry doesn't have, with no ID, about 3 to 5 µs (`capture.iokit.registry.path.missing`).
/// - IOSurfaceRoot by ID alone, about 64 to 66 µs (`capture.iokit.registry.id`), and every service, about 53 µs
///   averaged (`capture.iokit.registry.id.all`), as `IOServiceGetMatchingService` matches through the registry.
struct IOKitRegistryService: Equatable {
    /// The service's class, from `IOObjectGetClass`: `IOSurfaceRoot`.
    let className: String?
    /// The bundle ID of the service's driver: `com.apple.iokit.IOSurface`.
    let driverBundleID: String?

    /// Read the service an IOKit open connects to. Every registry object it gets is released.
    ///
    /// - Parameters:
    ///   - path: The service's registry path, as Endpoint Security gives it: `IOService:/IOResources/IOSurfaceRoot`.
    ///   - registryID: The service's registry ID. `nil` or 0 names none.
    /// - Returns: The service, or `nil` when neither names one that's in the registry now.
    static func read(path: String?, registryID: UInt64?) -> IOKitRegistryService? {
        let entry = entry(path: path, registryID: registryID ?? 0)
        guard entry != IO_OBJECT_NULL else { return nil }
        defer { IOObjectRelease(entry) }
        let className = className(of: entry)
        return IOKitRegistryService(className: className,
                                    driverBundleID: IOKitDriverBundle.driverBundleID(of: entry, className: className))
    }

    /// Look a service up by its path, keeping the entry only when its registry ID is `registryID` or there's no ID to
    /// check, else by its registry ID.
    ///
    /// - Parameters:
    ///   - path: The service's registry path.
    ///   - registryID: The service's registry ID. 0 names none.
    /// - Returns: The registry entry, which the caller releases, or `IO_OBJECT_NULL`.
    private static func entry(path: String?, registryID: UInt64) -> io_registry_entry_t {
        if let path, !path.isEmpty {
            let entry = IORegistryEntryFromPath(kIOMainPortDefault, path)
            if entry != IO_OBJECT_NULL {
                if registryID == 0 || self.registryID(of: entry) == registryID { return entry }
                IOObjectRelease(entry)
            }
        }
        return entry(registryID: registryID)
    }

    /// - Parameter registryID: A registry ID. 0 names none.
    /// - Returns: The registry entry with that ID, which the caller releases, or `IO_OBJECT_NULL`.
    private static func entry(registryID: UInt64) -> io_registry_entry_t {
        guard registryID != 0 else { return IO_OBJECT_NULL }
        /// `IOServiceGetMatchingService` consumes the matching dictionary.
        return IOServiceGetMatchingService(kIOMainPortDefault, IORegistryEntryIDMatching(registryID))
    }

    /// - Parameter entry: A registry entry.
    /// - Returns: Its registry ID, or `nil` when it can't be read.
    private static func registryID(of entry: io_registry_entry_t) -> UInt64? {
        var id: UInt64 = 0
        return IORegistryEntryGetRegistryEntryID(entry, &id) == KERN_SUCCESS ? id : nil
    }

    /// - Parameter entry: A registry entry.
    /// - Returns: Its class, or `nil` when it can't be read.
    private static func className(of entry: io_registry_entry_t) -> String? {
        var name = [CChar](repeating: 0, count: MemoryLayout<io_name_t>.size)
        guard IOObjectGetClass(entry, &name) == KERN_SUCCESS else { return nil }
        let value = String(cString: name)
        return value.isEmpty ? nil : value
    }
}
