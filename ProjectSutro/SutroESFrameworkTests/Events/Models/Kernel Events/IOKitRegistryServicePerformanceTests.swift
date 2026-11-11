//
//  IOKitRegistryServicePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import IOKit
@testable import SutroESFramework


// MARK: - Reading an IOKit open's service
/// Times what capturing an IOKit open adds: reading its service's class and driver from the IOKit registry
/// (``IOKitRegistryService``), by path and registry ID as Endpoint Security usually gives them, by registry ID alone
/// when it gives no path, and for a path the registry doesn't have.
final class IOKitRegistryServicePerformanceTests: PerformanceTestCase {
    /// Reads per sample of one service.
    private static let reads = 2_000

    /// IOSurfaceRoot read by its path, checked against its registry ID as capture does.
    func testReadByPath() throws {
        let id = try IOKitRegistryServiceTests.surfaceRootID()
        try benchmark("capture.iokit.registry.path", unit: "read", operations: Self.reads) {
            for _ in 0..<Self.reads {
                guard IOKitRegistryService.read(path: IOKitRegistryServiceTests.surfaceRoot, registryID: id) != nil
                else { throw BenchmarkFailure("IOSurfaceRoot wasn't read") }
            }
        }
    }

    /// IOSurfaceRoot read by its registry ID, without a path.
    func testReadByRegistryID() throws {
        let id = try IOKitRegistryServiceTests.surfaceRootID()
        try benchmark("capture.iokit.registry.id", unit: "read", operations: Self.reads) {
            for _ in 0..<Self.reads {
                guard IOKitRegistryService.read(path: nil, registryID: id) != nil
                else { throw BenchmarkFailure("IOSurfaceRoot wasn't read") }
            }
        }
    }

    /// Every service on this Mac read by its path and registry ID, as capture reads them: a path that finds a
    /// same-named sibling, or nothing, falls back to the ID.
    func testReadEveryServiceByPath() throws {
        let services = try listedServices()
        try benchmark("capture.iokit.registry.path.all", unit: "read", operations: services.count) {
            for service in services {
                _ = IOKitRegistryService.read(path: service.path, registryID: service.registryID)
            }
        }
    }

    /// Every service on this Mac read by its registry ID alone.
    func testReadEveryServiceByRegistryID() throws {
        let services = try listedServices()
        try benchmark("capture.iokit.registry.id.all", unit: "read", operations: services.count) {
            for service in services {
                _ = IOKitRegistryService.read(path: nil, registryID: service.registryID)
            }
        }
    }

    /// A path the registry doesn't have, with no registry ID to fall back to.
    func testReadAMissingPath() throws {
        try benchmark("capture.iokit.registry.path.missing", unit: "read", operations: Self.reads) {
            for _ in 0..<Self.reads {
                guard IOKitRegistryService.read(path: IOKitRegistryServiceTests.missingPath, registryID: 0) == nil
                else { throw BenchmarkFailure("\(IOKitRegistryServiceTests.missingPath) was read") }
            }
        }
    }

    /// - Returns: This Mac's services, listed outside the timing. A service that leaves the registry while the
    ///   benchmark runs costs a failed read, as it would at capture.
    /// - Throws: `XCTSkip` when the registry can't be walked.
    private func listedServices() throws -> [IOKitServicePlaneEntry] {
        let services = IOKitServicePlane.services()
        try XCTSkipIf(services.isEmpty, "This Mac's registry can't be walked")
        return services
    }
}
