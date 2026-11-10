//
//  IOKitUserClients.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Notable user clients
/// IOKit user client classes worth knowing when a process opens one, each with what it gives the process. Each is a
/// subclass of `IOUserClient` that the kernel of macOS 27.2 registered on a MacBook Pro (Mac17,3). Which of them a
/// Mac's kernel registers depends on its hardware and the kexts it loads: a virtual Mac (VirtualMac2,1) has no
/// `AppleMultitouchDeviceUserClient`. `IOKitUserClientsTests` checks the ones the running kernel has registered.
public enum IOKitUserClients {
    /// Each class's description, by its name as `user_client_class` gives it.
    public static let descriptions: [String: String] = [
        "IOHIDLibUserClient": "Reads input from a keyboard, mouse or other input device",
        "IOHIDParamUserClient": "Changes input settings, and can send fake keyboard and mouse input",
        "AppleKeyStoreUserClient":
            "The Mac's encryption key store: lock state, and the keys that protect files and keychain items",
        "IOFramebufferSharedUserClient": "Memory shared with an Intel Mac's display, such as the cursor",
        "IOMobileFramebufferUserClient": "Controls an Apple silicon display",
        "RootDomainUserClient": "Power management: sleep, wake, and keeping the Mac awake",
        "AppleSMCClient": "The System Management Controller: temperatures, fans and power",
        "IOBluetoothHCIUserClient": "Talks to the Bluetooth chip directly",
        "AppleUSBHostDeviceUserClient": "Talks to a USB device directly, from an app rather than a driver",
        "AppleUSBHostInterfaceUserClient":
            "Talks to one part of a USB device directly, from an app rather than a driver",
        "AppleMultitouchDeviceUserClient": "A trackpad's raw touch data",
    ]

    /// - Parameter className: A user client's class, as `user_client_class` gives it.
    /// - Returns: What opening it gives, or `nil` for a class the table doesn't have.
    public static func description(of className: String) -> String? {
        descriptions[className]
    }
}
