//
//  PerformanceEnvironment.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Performance environment
/// What a results file was measured on: the Mac, its macOS, and the Mac Monitor build. Two files are only comparable
/// benchmark by benchmark when their builds are both optimized; across Macs, the chip and cores say why they differ.
struct PerformanceEnvironment: Codable {
    /// The hardware.
    struct Machine: Codable {
        /// `hw.model`, such as `Mac17,3`.
        let model: String
        /// `machdep.cpu.brand_string`, such as `Apple M5` or `Apple M1 Max`.
        let chip: String
        /// Performance and efficiency cores (`hw.perflevel0` and `hw.perflevel1`), `nil` on an Intel Mac.
        let performanceCores, efficiencyCores: Int?
        /// `hw.logicalcpu`: every core, as the scheduler counts them.
        let logicalCores: Int
        /// `hw.memsize`.
        let memoryBytes: UInt64
        /// The test process's architecture, and is it translated by Rosetta?
        let architecture: String
        let translated: Bool

        /// This Mac.
        static let current = Machine(
            model: Sysctl.string("hw.model") ?? "unknown",
            chip: Sysctl.string("machdep.cpu.brand_string") ?? "unknown",
            performanceCores: Sysctl.integer("hw.perflevel0.physicalcpu"),
            efficiencyCores: Sysctl.integer("hw.perflevel1.physicalcpu"),
            logicalCores: Sysctl.integer("hw.logicalcpu") ?? ProcessInfo.processInfo.activeProcessorCount,
            memoryBytes: UInt64(Sysctl.integer("hw.memsize") ?? 0),
            architecture: Self.architecture,
            translated: Sysctl.integer("sysctl.proc_translated") == 1)

        /// The architecture this code was compiled for.
        private static var architecture: String {
            #if arch(arm64)
            return "arm64"
            #elseif arch(x86_64)
            return "x86_64"
            #else
            return "unknown"
            #endif
        }
    }

    /// macOS, and the state that slows a run down.
    struct System: Codable {
        /// Such as `27.2`, and its build (`kern.osversion`), such as `26B123`.
        let version: String
        let build: String
        /// `ProcessInfo`'s thermal state when the run started: anything but `nominal` throttles.
        let thermalState: String
        /// Was Low Power Mode on?
        let lowPowerMode: Bool

        /// macOS now.
        static var current: System {
            let version = ProcessInfo.processInfo.operatingSystemVersion
            let states: [ProcessInfo.ThermalState: String] = [.nominal: "nominal", .fair: "fair", .serious: "serious",
                                                              .critical: "critical"]
            return System(version: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
                          build: Sysctl.string("kern.osversion") ?? "unknown",
                          thermalState: states[ProcessInfo.processInfo.thermalState] ?? "unknown",
                          lowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled)
        }
    }

    /// The Mac Monitor build measured.
    struct Build: Codable {
        /// SutroESFramework's `CFBundleShortVersionString` and `CFBundleVersion`.
        let macMonitorVersion: String
        let macMonitorBuild: String
        /// The source's commit (``PerformanceRun/commit``).
        let commit: String?
        /// The build configuration (``PerformanceRun/configuration``).
        let configuration: String
        /// Was it compiled with optimization? Unoptimized numbers (Xcode's Community configuration) say little about
        /// the shipped app.
        let optimized: Bool

        /// The build these tests run.
        static var current: Build {
            let framework = Bundle(for: CoreDataController.self)
            let value = { (key: String) in framework.object(forInfoDictionaryKey: key) as? String ?? "unknown" }
            return Build(macMonitorVersion: value("CFBundleShortVersionString"),
                         macMonitorBuild: value("CFBundleVersion"), commit: PerformanceRun.commit,
                         configuration: PerformanceRun.configuration, optimized: !_isDebugAssertConfiguration())
        }
    }

    let machine: Machine
    let system: System
    let build: Build

    /// This Mac, macOS and build, now.
    static var current: PerformanceEnvironment {
        PerformanceEnvironment(machine: .current, system: .current, build: .current)
    }
}


// MARK: - sysctl
/// Reads `sysctlbyname(3)` values.
enum Sysctl {
    /// A string value.
    ///
    /// - Parameter name: The value's name, such as `hw.model`.
    /// - Returns: The string, or `nil` if there's no such value.
    static func string(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0 else { return nil }
        return String(cString: bytes)
    }

    /// An integer value, of whichever width the kernel keeps it in.
    ///
    /// - Parameter name: The value's name, such as `hw.memsize`.
    /// - Returns: The value, or `nil` if there's no such value.
    static func integer(_ name: String) -> Int? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        /// A 32-bit value fills only the low half.
        return size == MemoryLayout<Int32>.size ? Int(Int32(truncatingIfNeeded: value)) : Int(value)
    }
}
