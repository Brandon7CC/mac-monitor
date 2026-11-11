//
//  IOKitRegistryServiceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import IOKit
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Reading the service an IOKit open connects to
/// Pins ``IOKitRegistryService`` against this Mac's IOKit registry: a service is read by its path when the entry the
/// path finds has its registry ID, else by its registry ID, a nub without a personality is named by the driver that
/// published it, and an IOKit open captured at message version 10 and later carries both values.
final class IOKitRegistryServiceTests: XCTestCase {
    /// IOSurface's root service, which every Mac on macOS 11 and later has.
    static let surfaceRoot = "IOService:/IOResources/IOSurfaceRoot"
    /// A path no registry has.
    static let missingPath = "IOService:/IOResources/NoSuchService"

    /// - Returns: IOSurfaceRoot's registry ID.
    /// - Throws: `XCTSkip` when this Mac's registry doesn't have it.
    static func surfaceRootID() throws -> UInt64 {
        guard let id = IOKitServicePlane.registryID(resolving: surfaceRoot) else {
            throw XCTSkip("No \(surfaceRoot) in this Mac's registry")
        }
        return id
    }

    /// - Returns: The power management root domain's registry ID, a service other than IOSurfaceRoot.
    /// - Throws: `XCTSkip` when this Mac's registry doesn't have it.
    private func rootDomainID() throws -> UInt64 {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"))
        guard entry != IO_OBJECT_NULL else { throw XCTSkip("No IOPMrootDomain") }
        defer { IOObjectRelease(entry) }
        var id: UInt64 = 0
        XCTAssertEqual(IORegistryEntryGetRegistryEntryID(entry, &id), KERN_SUCCESS)
        return id
    }

    /// An IOKit open captured from Endpoint Security's struct.
    ///
    /// - Parameters:
    ///   - version: The message's version.
    ///   - path: The parent path, or `nil` for a NULL token.
    ///   - registryID: The parent registry ID.
    /// - Returns: The event.
    private func captured(version: UInt32 = 10, path: String?, registryID: UInt64 = 0) -> IOKitOpenEvent {
        let fixture = rawMessage(version: version, type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN)
        fixture.message.pointee.event.iokit_open.user_client_class = fixture.token("IOSurfaceRootUserClient")
        fixture.message.pointee.event.iokit_open.parent_path = fixture.token(path)
        fixture.message.pointee.event.iokit_open.parent_registry_id = registryID
        return IOKitOpenEvent(from: fixture.raw)
    }

    // MARK: Reading

    /// A real path reads as its class and an Apple driver's bundle ID.
    func testReadsAPath() throws {
        _ = try Self.surfaceRootID()
        let service = try XCTUnwrap(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: nil))
        XCTAssertEqual(service.className, "IOSurfaceRoot")
        let driver = try XCTUnwrap(service.driverBundleID)
        XCTAssertTrue(driver.hasPrefix("com.apple."), driver)
    }

    /// A path whose entry has the registry ID given, or with no ID to check, reads as that entry.
    func testAPathAndItsRegistryIDReadThePath() throws {
        let id = try Self.surfaceRootID()
        let byPath = try XCTUnwrap(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: nil))
        XCTAssertEqual(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: id), byPath)
        XCTAssertEqual(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: 0), byPath)
    }

    /// When the entry a path finds has another registry ID, the ID names the service: a path can name a sibling of
    /// the service that was opened. An ID the registry no longer has reads as nothing, even with a path that resolves.
    func testARegistryIDThatDisagreesWithThePathWins() throws {
        _ = try Self.surfaceRootID()
        let rootDomain = try rootDomainID()
        let service = try XCTUnwrap(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: rootDomain))
        XCTAssertEqual(service.className, "IOPMrootDomain")
        XCTAssertNil(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: UInt64.max))
    }

    /// A path the registry doesn't have falls back to the registry ID, when there is one.
    func testAPathNotInTheRegistryFallsBackToTheRegistryID() throws {
        let id = try Self.surfaceRootID()
        let byPath = try XCTUnwrap(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: nil))
        XCTAssertEqual(IOKitRegistryService.read(path: Self.missingPath, registryID: id), byPath)
        XCTAssertEqual(IOKitRegistryService.read(path: "/synthetic/parent", registryID: id), byPath)
        XCTAssertNil(IOKitRegistryService.read(path: Self.missingPath, registryID: 0))
        XCTAssertNil(IOKitRegistryService.read(path: Self.missingPath, registryID: nil))
    }

    /// Without a path, the registry ID finds the same service.
    func testReadsARegistryIDWithoutAPath() throws {
        let id = try Self.surfaceRootID()
        let byPath = IOKitRegistryService.read(path: Self.surfaceRoot, registryID: nil)
        XCTAssertEqual(IOKitRegistryService.read(path: "", registryID: id), byPath)
        XCTAssertEqual(IOKitRegistryService.read(path: nil, registryID: id), byPath)
    }

    /// Nothing is read without a path or a registry ID, or for ones the registry doesn't have.
    func testReadsNothingForUnknownServices() {
        XCTAssertNil(IOKitRegistryService.read(path: nil, registryID: nil))
        XCTAssertNil(IOKitRegistryService.read(path: "", registryID: 0))
        XCTAssertNil(IOKitRegistryService.read(path: "/synthetic/parent", registryID: nil))
        XCTAssertNil(IOKitRegistryService.read(path: Self.missingPath, registryID: nil))
        XCTAssertNil(IOKitRegistryService.read(path: nil, registryID: UInt64.max))
    }

    /// Every service on this Mac reads as itself from its path and registry ID, including those whose path finds a
    /// same-named sibling or nothing. A service that leaves the registry while the test runs, or one whose path is
    /// ambiguous and that was never registered for matching, so its ID finds nothing, reads as nothing.
    func testEveryServiceReadsAsItself() throws {
        let services = IOKitServicePlane.services()
        try XCTSkipIf(services.isEmpty, "This Mac's registry can't be walked")
        var read = 0
        var ambiguous = 0
        for service in services {
            if IOKitServicePlane.registryID(resolving: service.path) != service.registryID { ambiguous += 1 }
            guard let found = IOKitRegistryService.read(path: service.path, registryID: service.registryID) else {
                continue
            }
            read += 1
            XCTAssertEqual(found.className, service.className, "\(service.path) (\(service.registryID))")
        }
        XCTAssertGreaterThan(read, services.count / 2, "\(read) of \(services.count) services read")
        print("[IOKitRegistryServiceTests] \(read) of \(services.count) services read, \(ambiguous) of them by an "
              + "ambiguous or unresolvable path")
    }

    /// The power management root domain is a nub the platform publishes, with no personality of its own: it's named by
    /// the nearest provider that has a bundle ID.
    func testANubIsNamedByItsProvider() throws {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"))
        guard entry != IO_OBJECT_NULL else { throw XCTSkip("No IOPMrootDomain") }
        defer { IOObjectRelease(entry) }
        let own = IORegistryEntryCreateCFProperty(entry, IOKitDriverBundle.propertyKey as CFString,
                                                  kCFAllocatorDefault, 0)?.takeRetainedValue()
        guard own == nil else { throw XCTSkip("IOPMrootDomain has a bundle ID of its own on this Mac") }
        var path = [CChar](repeating: 0, count: MemoryLayout<io_string_t>.size)
        XCTAssertEqual(IORegistryEntryGetPath(entry, kIOServicePlane, &path), KERN_SUCCESS)
        let service = try XCTUnwrap(IOKitRegistryService.read(path: String(cString: path), registryID: nil))
        XCTAssertEqual(service.className, "IOPMrootDomain")
        XCTAssertTrue(service.driverBundleID?.hasPrefix("com.apple.") ?? false, "\(service)")
    }

    // MARK: Capture

    /// An open captured at message version 10 carries the service's class and driver, from its path, or from its
    /// registry ID when the path is empty or NULL.
    func testCaptureReadsTheService() throws {
        let id = try Self.surfaceRootID()
        let expected = try XCTUnwrap(IOKitRegistryService.read(path: Self.surfaceRoot, registryID: nil))
        for event in [captured(path: Self.surfaceRoot, registryID: id), captured(path: "", registryID: id),
                      captured(path: nil, registryID: id)] {
            XCTAssertEqual(event.parent_class, "IOSurfaceRoot")
            XCTAssertEqual(event.driver_bundle_id, expected.driverBundleID)
        }
    }

    /// An open whose path the registry doesn't have, or whose path finds another entry, is read by its registry ID.
    func testCaptureFallsBackToTheRegistryID() throws {
        let id = try Self.surfaceRootID()
        let rootDomain = try rootDomainID()
        XCTAssertEqual(captured(path: Self.missingPath, registryID: id).parent_class, "IOSurfaceRoot")
        XCTAssertEqual(captured(path: Self.surfaceRoot, registryID: rootDomain).parent_class, "IOPMrootDomain")
    }

    /// Before message version 10 Endpoint Security names no parent, so nothing is read. A service the registry no
    /// longer has reads as nothing.
    func testCaptureWithoutAServiceReadsNothing() throws {
        let id = try Self.surfaceRootID()
        let early = captured(version: 9, path: Self.surfaceRoot, registryID: id)
        XCTAssertNil(early.parent_path)
        XCTAssertNil(early.parent_class)
        XCTAssertNil(early.driver_bundle_id)
        for gone in [captured(path: Self.missingPath, registryID: 0),
                     captured(path: Self.missingPath, registryID: UInt64.max)] {
            XCTAssertNil(gone.parent_class)
            XCTAssertNil(gone.driver_bundle_id)
        }
    }
}
