//
//  ThreadStateFlavor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Thread state flavors
/// The names of thread state flavors (`thread_state_flavor_t`), whose values stand for different states on each
/// architecture.
///
/// The tables hold the SDK's values as literals, so both are compiled, and tested, on either architecture.
enum ThreadStateFlavor {
    /// Apple silicon's flavors (`mach/arm/thread_status.h`).
    static let arm64: [Int32: String] = {
        var names: [Int32: String] = [
            1: "ARM_THREAD_STATE", 2: "ARM_VFP_STATE", 3: "ARM_EXCEPTION_STATE", 4: "ARM_DEBUG_STATE",
            5: "THREAD_STATE_NONE", 6: "ARM_THREAD_STATE64", 7: "ARM_EXCEPTION_STATE64", 9: "ARM_THREAD_STATE32",
            10: "ARM_EXCEPTION_STATE64_V2", 14: "ARM_DEBUG_STATE32", 15: "ARM_DEBUG_STATE64", 16: "ARM_NEON_STATE",
            17: "ARM_NEON_STATE64", 18: "ARM_CPMU_STATE64", 27: "ARM_PAGEIN_STATE", 28: "ARM_SME_STATE",
            29: "ARM_SVE_Z_STATE1", 30: "ARM_SVE_Z_STATE2", 31: "ARM_SVE_P_STATE", 48: "ARM_SME2_STATE",
        ]
        /// `ARM_SME_ZA_STATE1` to `ARM_SME_ZA_STATE16` are 32 to 47.
        for index in 1...16 {
            names[Int32(31 + index)] = "ARM_SME_ZA_STATE\(index)"
        }
        return names
    }()
    
    /// Intel's flavors (`mach/i386/thread_status.h`). 14 and 15 are the kernel's own.
    static let x86_64: [Int32: String] = [
        1: "x86_THREAD_STATE32", 2: "x86_FLOAT_STATE32", 3: "x86_EXCEPTION_STATE32", 4: "x86_THREAD_STATE64",
        5: "x86_FLOAT_STATE64", 6: "x86_EXCEPTION_STATE64", 7: "x86_THREAD_STATE", 8: "x86_FLOAT_STATE",
        9: "x86_EXCEPTION_STATE", 10: "x86_DEBUG_STATE32", 11: "x86_DEBUG_STATE64", 12: "x86_DEBUG_STATE",
        13: "THREAD_STATE_NONE", 16: "x86_AVX_STATE32", 17: "x86_AVX_STATE64", 18: "x86_AVX_STATE",
        19: "x86_AVX512_STATE32", 20: "x86_AVX512_STATE64", 21: "x86_AVX512_STATE", 22: "x86_PAGEIN_STATE",
        23: "x86_THREAD_FULL_STATE64", 24: "x86_INSTRUCTION_STATE", 25: "x86_LAST_BRANCH_STATE",
    ]
    
    /// This Mac's flavors. An event's flavor is named on the Mac that reads it: eslogger doesn't record the
    /// architecture.
    static var native: [Int32: String] {
        #if arch(arm64)
        arm64
        #else
        x86_64
        #endif
    }
    
    /// Each name's flavor: this Mac's, then the other architecture's. Only `THREAD_STATE_NONE` is in both.
    private static let flavors: [String: Int32] = {
        var flavors = [String: Int32]()
        for table in [x86_64, arm64, native] {
            flavors.merge(table.map { ($0.value, $0.key) }) { _, later in later }
        }
        return flavors
    }()
    
    /// The name of a flavor on this Mac's architecture.
    ///
    /// - Parameter flavor: A flavor.
    /// - Returns: Its name, or `nil` if it has none.
    static func name(of flavor: Int32) -> String? {
        native[flavor]
    }
    
    /// The flavor a name stands for: this Mac's for `THREAD_STATE_NONE`, otherwise the one architecture's that has it.
    ///
    /// - Parameter name: A flavor's name, as Mac Monitor wrote `thread_state` before 2.2.0.
    /// - Returns: Its value, or `nil` for a name neither architecture has.
    static func flavor(named name: String) -> Int32? {
        flavors[name]
    }
}
