//
//  IOKitDriverBundleTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import IOKit
@testable import SutroESFramework


// MARK: - Naming a service's driver
/// Pins ``IOKitDriverBundle``: a service's `CFBundleIdentifier` names its driver, unless that names an Apple bundle,
/// or none, and the kext that defines the service's class is a third party's. So a third-party kext can't pass as
/// Apple by setting the property.
final class IOKitDriverBundleTests: XCTestCase {
    /// A third-party class's kext is the driver, whatever Apple bundle the property names.
    func testAThirdPartyClassOverridesAnAppleProperty() {
        let driver = IOKitDriverBundle.resolve(property: "com.apple.iokit.IOSurface", classBundle: "com.example.kext")
        XCTAssertEqual(driver, "com.example.kext")
        XCTAssertEqual(IOKitDriverBundle.resolve(property: "__kernel__", classBundle: "com.example.kext"),
                       "com.example.kext")
        XCTAssertEqual(IOKitDriverBundle.resolve(property: nil, classBundle: "com.example.kext"), "com.example.kext")
    }

    /// A class the kernel or an Apple kext defines, or one with no bundle, leaves the property as the driver: a dext's
    /// service has an Apple family's class.
    func testAnAppleOrKernelClassKeepsTheProperty() {
        for classBundle in ["__kernel__", "com.apple.iokit.IOHIDFamily", "", nil] as [String?] {
            XCTAssertEqual(IOKitDriverBundle.resolve(property: "com.apple.iokit.IOSurface", classBundle: classBundle),
                           "com.apple.iokit.IOSurface", "\(classBundle ?? "nil")")
            XCTAssertNil(IOKitDriverBundle.resolve(property: nil, classBundle: classBundle))
        }
    }

    /// A third-party property is the driver as it is, with no class lookup.
    func testAThirdPartyPropertyIsKeptWithoutAClassLookup() {
        var lookups = 0
        func classBundle() -> String? {
            lookups += 1
            return "com.other.kext"
        }
        XCTAssertEqual(IOKitDriverBundle.resolve(property: "com.example.dext", classBundle: classBundle()),
                       "com.example.dext")
        XCTAssertEqual(lookups, 0)
        _ = IOKitDriverBundle.resolve(property: "com.apple.iokit.IOSurface", classBundle: classBundle())
        XCTAssertEqual(lookups, 1)
    }

    /// The kernel and Apple's bundles are Apple's, and only on an exact prefix.
    func testIsApple() {
        XCTAssertTrue(IOKitDriverBundle.isApple("__kernel__"))
        XCTAssertTrue(IOKitDriverBundle.isApple("com.apple.iokit.IOSurface"))
        XCTAssertFalse(IOKitDriverBundle.isApple("com.applesauce.kext"))
        XCTAssertFalse(IOKitDriverBundle.isApple("com.example.com.apple."))
        XCTAssertFalse(IOKitDriverBundle.isApple(""))
    }

    /// IOSurfaceRoot is a class an Apple kext defines, so its driver stays Apple's. IOPMrootDomain's is the kernel's.
    func testAKnownAppleClassStaysApple() throws {
        _ = try IOKitRegistryServiceTests.surfaceRootID()
        let classBundle = try XCTUnwrap(IOKitDriverBundle.classBundle(of: "IOSurfaceRoot"))
        XCTAssertTrue(classBundle.hasPrefix("com.apple."), classBundle)
        let service = try XCTUnwrap(IOKitRegistryService.read(path: IOKitRegistryServiceTests.surfaceRoot,
                                                               registryID: nil))
        XCTAssertTrue(service.driverBundleID?.hasPrefix("com.apple.") ?? false, "\(service)")
        XCTAssertEqual(IOKitDriverBundle.classBundle(of: "IOPMrootDomain"), "__kernel__")
        XCTAssertNil(IOKitDriverBundle.classBundle(of: "NoSuchClass"))
    }

    /// Every service on this Mac whose class a third-party kext defines has a third party's driver, whatever Apple
    /// bundle its property names. A Mac without third-party kexts has none to check.
    func testThirdPartyClassesNameAThirdPartyDriver() {
        for service in IOKitServicePlane.services() {
            guard let classBundle = IOKitDriverBundle.classBundle(of: service.className),
                  !IOKitDriverBundle.isApple(classBundle),
                  let found = IOKitRegistryService.read(path: service.path, registryID: service.registryID)
            else { continue }
            let driver = found.driverBundleID ?? ""
            XCTAssertFalse(driver.isEmpty || IOKitDriverBundle.isApple(driver), "\(service.path): \(driver)")
        }
    }
}
