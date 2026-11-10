//
//  IOKitUserClientsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import IOKit
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Notable user clients and service names
/// Pins ``IOKitUserClients``: each class it describes that the running kernel has registered is a user client, and
/// each description is one plain line. Also pins the name Event Facts gives the service an IOKit open connects to.
final class IOKitUserClientsTests: XCTestCase {
    /// The table's classes, and only them, have a description, each one plain line.
    func testDescriptions() {
        XCTAssertEqual(IOKitUserClients.descriptions.count, 11)
        for (name, description) in IOKitUserClients.descriptions {
            XCTAssertEqual(IOKitUserClients.description(of: name), description, name)
            XCTAssertFalse(description.isEmpty, name)
            XCTAssertFalse(description.contains("\n"), name)
            XCTAssertFalse(description.hasSuffix("."), name)
        }
        XCTAssertEqual(IOKitUserClients.description(of: "IOHIDLibUserClient"),
                       "Reads input from a keyboard, mouse or other input device")
        XCTAssertNotNil(IOKitUserClients.description(of: "IOHIDParamUserClient"))
        /// Names are exact: a prefix, another case, or a class this Mac doesn't have, has none.
        XCTAssertNil(IOKitUserClients.description(of: "IOHIDLib"))
        XCTAssertNil(IOKitUserClients.description(of: "iohidlibuserclient"))
        XCTAssertNil(IOKitUserClients.description(of: "IOUSBHostDeviceUserClient"))
        XCTAssertNil(IOKitUserClients.description(of: ""))
    }

    /// Every class the table describes that the running kernel has registered is an `IOUserClient`. Which are
    /// registered depends on the Mac's hardware and the kexts it loads, so a class that isn't is checked against the
    /// kexts' Info.plists, and skipped with a message when none names it.
    func testEveryRegisteredClassIsAUserClient() throws {
        let kextClasses = KextUserClientClasses.named()
        var registered = 0
        for name in IOKitUserClients.descriptions.keys.sorted() {
            let superclasses = ancestry(of: name)
            switch UserClientCheck(superclasses: superclasses, namedByKext: kextClasses.contains(name)) {
            case .registered(let isUserClient):
                registered += 1
                XCTAssertTrue(isUserClient, "\(name): \(superclasses)")
            case .namedByKext:
                note("\(name) isn't registered: a kext's Info.plist names it as its \(KextUserClientClasses.key)")
            case .unverified:
                note("Skipped \(name): it isn't registered, and no kext's Info.plist under "
                     + "\(KextUserClientClasses.extensions.path) names it")
            }
        }
        try XCTSkipIf(registered == 0, "The running kernel has registered none of the table's classes")
        XCTAssertEqual(ancestry(of: "IOUSBHostDeviceUserClient"), [], "No such class on macOS 27")
    }

    /// A class the kernel hasn't registered, as a virtual Mac has no `AppleMultitouchDeviceUserClient`, is checked
    /// against the kexts' Info.plists, and is skipped, not failed, when none names it.
    func testAClassTheKernelHasntRegisteredIsntRequired() {
        XCTAssertEqual(UserClientCheck(superclasses: [], namedByKext: false), .unverified)
        XCTAssertEqual(UserClientCheck(superclasses: [], namedByKext: true), .namedByKext)
        XCTAssertEqual(UserClientCheck(superclasses: ["IOUserClient2022", "IOUserClient", "IOService"],
                                       namedByKext: false), .registered(isUserClient: true))
        XCTAssertEqual(UserClientCheck(superclasses: ["IOService", "IORegistryEntry"], namedByKext: true),
                       .registered(isUserClient: false))
    }

    /// The installed kexts' Info.plists name IOHIDFamily's user client, which every Mac has, whether or not it's
    /// loaded.
    func testKextInfoPlistsNameUserClients() throws {
        let classes = KextUserClientClasses.named()
        try XCTSkipIf(classes.isEmpty, "No kext Info.plists under \(KextUserClientClasses.extensions.path)")
        XCTAssertTrue(classes.contains("IOHIDLibUserClient"), "\(classes.count) classes")
        XCTAssertTrue(KextUserClientClasses.named(under: URL(fileURLWithPath: "/synthetic/none")).isEmpty)
    }

    /// Record a message in the test's report and its log.
    ///
    /// - Parameter message: What the check found.
    private func note(_ message: String) {
        print("[IOKitUserClientsTests] \(message)")
        XCTContext.runActivity(named: message) { _ in }
    }

    /// - Parameter name: A class's name.
    /// - Returns: Its superclasses in the running kernel, nearest first, or none for a class it hasn't registered.
    private func ancestry(of name: String) -> [String] {
        var names: [String] = []
        var current = name
        while names.count < 32,
              let superclass = IOObjectCopySuperclassForClass(current as CFString)?.takeRetainedValue() as String? {
            names.append(superclass)
            current = superclass
        }
        return names
    }

    /// A service is named by its class, else by its registry path's last component, which names the entry.
    func testServiceNames() {
        let path = "IOService:/AppleARMPE/IOPMrootDomain"
        XCTAssertEqual(ESIOKitOpenEvent.serviceName(className: "IOPMrootDomain", path: "/synthetic/parent"),
                       "IOPMrootDomain")
        XCTAssertEqual(ESIOKitOpenEvent.serviceName(className: nil, path: path), "IOPMrootDomain")
        XCTAssertEqual(ESIOKitOpenEvent.serviceName(className: "", path: path), "IOPMrootDomain")
        XCTAssertEqual(ESIOKitOpenEvent.serviceName(className: nil, path: "IOService:/IOResources/IOSurfaceRoot/"),
                       "IOSurfaceRoot")
        XCTAssertNil(ESIOKitOpenEvent.serviceName(className: nil, path: "IOService:/"))
        XCTAssertNil(ESIOKitOpenEvent.serviceName(className: nil, path: ""))
        XCTAssertNil(ESIOKitOpenEvent.serviceName(className: nil, path: nil))
    }

    /// A stored IOKit open names its service and describes its user client.
    func testStoredEventNamesItsService() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("RootDomainUserClient")
        fixture.message.pointee.event.iokit_open.parent_path = fixture.token("/synthetic/IOPMrootDomain")
        withStoredEvent(Message(from: fixture.raw)) { stored in
            let event = stored.event.iokit_open
            XCTAssertNil(event?.parent_class, "No such path in the registry")
            XCTAssertEqual(event?.serviceName, "IOPMrootDomain")
            XCTAssertEqual(event?.userClientDescription, "Power management: sleep, wake, and keeping the Mac awake")
        }
    }
}


// MARK: - Checking one class
/// What the running kernel and the installed kexts say about one class of ``IOKitUserClients``.
enum UserClientCheck: Equatable {
    /// The kernel has registered it, and it is or isn't a subclass of `IOUserClient`.
    case registered(isUserClient: Bool)
    /// The kernel hasn't registered it, and a kext's Info.plist names it as a user client.
    case namedByKext
    /// The kernel hasn't registered it, and no kext's Info.plist names it.
    case unverified

    /// - Parameters:
    ///   - superclasses: Its superclasses in the running kernel, nearest first: none for a class it hasn't registered.
    ///   - namedByKext: Whether a kext's Info.plist names it as an `IOUserClientClass`.
    init(superclasses: [String], namedByKext: Bool) {
        if !superclasses.isEmpty {
            self = .registered(isUserClient: superclasses.contains("IOUserClient"))
        } else {
            self = namedByKext ? .namedByKext : .unverified
        }
    }
}
