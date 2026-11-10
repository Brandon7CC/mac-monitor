//
//  IOKitDriverBundle.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import IOKit


// MARK: - The driver an IOKit service belongs to
/// Names the bundle of the driver an IOKit service belongs to, from two sources the kernel keeps apart.
///
/// The first is the `CFBundleIdentifier` registry property, the service's own or else its nearest provider's
/// (``property(of:)``). A service matched from a personality has its own: its kext's, or for a DriverKit dext the
/// dext's bundle ID (`com.apple.AppleUserHIDDrivers`). `IOUserServerName` isn't read: it names the dext's server,
/// which needn't be its bundle ID (`com.apple.driverkit.AppleUserHIDDrivers`). A nub a driver publishes, such as
/// `IOPMrootDomain` or an I2C device, has no personality, so it's named by the nearest provider that has one, the
/// driver that published it.
///
/// A kext can set that property on its own service, or on a nub it publishes, to any value. So when it names an Apple
/// bundle, or none, the service's class is checked too (``classBundle(of:)``): `IOObjectCopyBundleIdentifierForClass`
/// names the kext that defines the class, from the kernel's class registry, which a service can't change, and a
/// third-party kext can't define a class an Apple kext defines. When that kext isn't the kernel (`__kernel__`) or
/// Apple's (`com.apple.`), it's the driver. Otherwise the property stands: a dext's service has a class an Apple family
/// defines (`com.apple.iokit.IOHIDFamily`), and a nub's class is often the kernel's.
enum IOKitDriverBundle {
    /// The registry property naming a driver's bundle, which a service gets from the personality it matched.
    static let propertyKey = "CFBundleIdentifier"
    /// What `IOObjectCopyBundleIdentifierForClass` names a class the kernel itself defines by.
    static let kernelBundleID = "__kernel__"
    /// The prefix of every Apple bundle ID.
    static let applePrefix = "com.apple."

    /// - Parameters:
    ///   - entry: A registry entry.
    ///   - className: Its class, from `IOObjectGetClass`, or `nil` when it couldn't be read.
    /// - Returns: The bundle ID of the entry's driver, or `nil` when neither source names one.
    static func driverBundleID(of entry: io_registry_entry_t, className: String?) -> String? {
        resolve(property: property(of: entry), classBundle: className.flatMap(classBundle(of:)))
    }

    /// Choose between the two sources. `classBundle` is read only when `property` names an Apple bundle or none, so a
    /// third-party property costs no class lookup.
    ///
    /// - Parameters:
    ///   - property: The `CFBundleIdentifier` the registry search found.
    ///   - classBundle: The bundle that defines the entry's class.
    /// - Returns: `classBundle` when it's a third party's and `property` isn't, else `property`.
    static func resolve(property: String?, classBundle: @autoclosure () -> String?) -> String? {
        if let property, !isApple(property) { return property }
        guard let classBundle = classBundle(), !classBundle.isEmpty, !isApple(classBundle) else { return property }
        return classBundle
    }

    /// - Parameter bundleID: A bundle ID, as either source gives it.
    /// - Returns: Whether it's the kernel's or Apple's.
    static func isApple(_ bundleID: String) -> Bool {
        bundleID == kernelBundleID || bundleID.hasPrefix(applePrefix)
    }

    /// The entry's own `CFBundleIdentifier`, else the nearest provider's in the service plane. One registry call
    /// searches the entry and then its providers.
    ///
    /// - Parameter entry: A registry entry.
    /// - Returns: The bundle ID, or `nil` when neither the entry nor a provider has one.
    static func property(of entry: io_registry_entry_t) -> String? {
        let options = IOOptionBits(kIORegistryIterateRecursively | kIORegistryIterateParents)
        let value = IORegistryEntrySearchCFProperty(entry, kIOServicePlane, propertyKey as CFString,
                                                    kCFAllocatorDefault, options)
        return nonEmpty(value as? String)
    }

    /// - Parameter className: A class the kernel has registered.
    /// - Returns: The bundle ID of the kext that defines it, `__kernel__` for the kernel's own, or `nil` for a class
    ///   the kernel hasn't registered.
    static func classBundle(of className: String) -> String? {
        nonEmpty(IOObjectCopyBundleIdentifierForClass(className as CFString)?.takeRetainedValue() as String?)
    }

    /// - Parameter value: A string read from the registry.
    /// - Returns: The string, or `nil` for none or an empty one.
    private static func nonEmpty(_ value: String?) -> String? {
        value?.isEmpty == false ? value : nil
    }
}
