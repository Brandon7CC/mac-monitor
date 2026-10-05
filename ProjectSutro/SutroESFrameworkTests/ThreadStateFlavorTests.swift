//
//  ThreadStateFlavorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Thread state flavor names
/// Pins the names of thread state flavors: each architecture's table matches its SDK header, a flavor is named on this
/// Mac's architecture, and a name Mac Monitor wrote before 2.2.0 maps back to its flavor on either architecture.
final class ThreadStateFlavorTests: XCTestCase {
    #if arch(arm64)
    /// Every Apple silicon flavor has the SDK's value.
    func testArm64TableMatchesSDK() {
        let sdk: [(Int32, String)] = [
            (ARM_THREAD_STATE, "ARM_THREAD_STATE"), (ARM_VFP_STATE, "ARM_VFP_STATE"),
            (ARM_EXCEPTION_STATE, "ARM_EXCEPTION_STATE"), (ARM_DEBUG_STATE, "ARM_DEBUG_STATE"),
            (THREAD_STATE_NONE, "THREAD_STATE_NONE"), (ARM_THREAD_STATE64, "ARM_THREAD_STATE64"),
            (ARM_EXCEPTION_STATE64, "ARM_EXCEPTION_STATE64"), (ARM_THREAD_STATE32, "ARM_THREAD_STATE32"),
            (ARM_EXCEPTION_STATE64_V2, "ARM_EXCEPTION_STATE64_V2"), (ARM_DEBUG_STATE32, "ARM_DEBUG_STATE32"),
            (ARM_DEBUG_STATE64, "ARM_DEBUG_STATE64"), (ARM_NEON_STATE, "ARM_NEON_STATE"),
            (ARM_NEON_STATE64, "ARM_NEON_STATE64"), (ARM_CPMU_STATE64, "ARM_CPMU_STATE64"),
            (ARM_PAGEIN_STATE, "ARM_PAGEIN_STATE"), (ARM_SME_STATE, "ARM_SME_STATE"),
            (ARM_SVE_Z_STATE1, "ARM_SVE_Z_STATE1"), (ARM_SVE_Z_STATE2, "ARM_SVE_Z_STATE2"),
            (ARM_SVE_P_STATE, "ARM_SVE_P_STATE"), (ARM_SME_ZA_STATE1, "ARM_SME_ZA_STATE1"),
            (ARM_SME_ZA_STATE2, "ARM_SME_ZA_STATE2"), (ARM_SME_ZA_STATE3, "ARM_SME_ZA_STATE3"),
            (ARM_SME_ZA_STATE4, "ARM_SME_ZA_STATE4"), (ARM_SME_ZA_STATE5, "ARM_SME_ZA_STATE5"),
            (ARM_SME_ZA_STATE6, "ARM_SME_ZA_STATE6"), (ARM_SME_ZA_STATE7, "ARM_SME_ZA_STATE7"),
            (ARM_SME_ZA_STATE8, "ARM_SME_ZA_STATE8"), (ARM_SME_ZA_STATE9, "ARM_SME_ZA_STATE9"),
            (ARM_SME_ZA_STATE10, "ARM_SME_ZA_STATE10"), (ARM_SME_ZA_STATE11, "ARM_SME_ZA_STATE11"),
            (ARM_SME_ZA_STATE12, "ARM_SME_ZA_STATE12"), (ARM_SME_ZA_STATE13, "ARM_SME_ZA_STATE13"),
            (ARM_SME_ZA_STATE14, "ARM_SME_ZA_STATE14"), (ARM_SME_ZA_STATE15, "ARM_SME_ZA_STATE15"),
            (ARM_SME_ZA_STATE16, "ARM_SME_ZA_STATE16"), (ARM_SME2_STATE, "ARM_SME2_STATE"),
        ]
        for (flavor, name) in sdk {
            XCTAssertEqual(ThreadStateFlavor.arm64[flavor], name, name)
        }
        XCTAssertEqual(ThreadStateFlavor.arm64.count, sdk.count)
        XCTAssertEqual(ThreadStateFlavor.name(of: ARM_THREAD_STATE64), "ARM_THREAD_STATE64")
    }
    #endif
    
    #if arch(x86_64)
    /// Every Intel flavor has the SDK's value.
    func testX86TableMatchesSDK() {
        let sdk: [(Int32, String)] = [
            (x86_THREAD_STATE32, "x86_THREAD_STATE32"), (x86_FLOAT_STATE32, "x86_FLOAT_STATE32"),
            (x86_EXCEPTION_STATE32, "x86_EXCEPTION_STATE32"), (x86_THREAD_STATE64, "x86_THREAD_STATE64"),
            (x86_FLOAT_STATE64, "x86_FLOAT_STATE64"), (x86_EXCEPTION_STATE64, "x86_EXCEPTION_STATE64"),
            (x86_THREAD_STATE, "x86_THREAD_STATE"), (x86_FLOAT_STATE, "x86_FLOAT_STATE"),
            (x86_EXCEPTION_STATE, "x86_EXCEPTION_STATE"), (x86_DEBUG_STATE32, "x86_DEBUG_STATE32"),
            (x86_DEBUG_STATE64, "x86_DEBUG_STATE64"), (x86_DEBUG_STATE, "x86_DEBUG_STATE"),
            (THREAD_STATE_NONE, "THREAD_STATE_NONE"), (x86_AVX_STATE32, "x86_AVX_STATE32"),
            (x86_AVX_STATE64, "x86_AVX_STATE64"), (x86_AVX_STATE, "x86_AVX_STATE"),
            (x86_AVX512_STATE32, "x86_AVX512_STATE32"), (x86_AVX512_STATE64, "x86_AVX512_STATE64"),
            (x86_AVX512_STATE, "x86_AVX512_STATE"), (x86_PAGEIN_STATE, "x86_PAGEIN_STATE"),
            (x86_THREAD_FULL_STATE64, "x86_THREAD_FULL_STATE64"), (x86_INSTRUCTION_STATE, "x86_INSTRUCTION_STATE"),
            (x86_LAST_BRANCH_STATE, "x86_LAST_BRANCH_STATE"),
        ]
        for (flavor, name) in sdk {
            XCTAssertEqual(ThreadStateFlavor.x86_64[flavor], name, name)
        }
        XCTAssertEqual(ThreadStateFlavor.x86_64.count, sdk.count)
        XCTAssertEqual(ThreadStateFlavor.name(of: x86_THREAD_STATE64), "x86_THREAD_STATE64")
    }
    #endif
    
    /// The Intel table on any Mac: `x86_AVX_STATE64` has its own name (Mac Monitor named it `x86_THREAD_STATE32`
    /// before 2.2.0), and the kernel's own 14 has none.
    func testX86TableLiterals() {
        XCTAssertEqual(ThreadStateFlavor.x86_64[4], "x86_THREAD_STATE64")
        XCTAssertEqual(ThreadStateFlavor.x86_64[17], "x86_AVX_STATE64")
        XCTAssertEqual(ThreadStateFlavor.x86_64[13], "THREAD_STATE_NONE")
        XCTAssertNil(ThreadStateFlavor.x86_64[14])
    }
    
    /// Every name maps back to its flavor, on either architecture; `THREAD_STATE_NONE`, in both, to this Mac's.
    func testReverseLookup() {
        for table in [ThreadStateFlavor.arm64, ThreadStateFlavor.x86_64] {
            for (flavor, name) in table where name != "THREAD_STATE_NONE" {
                XCTAssertEqual(ThreadStateFlavor.flavor(named: name), flavor, name)
            }
        }
        XCTAssertEqual(ThreadStateFlavor.flavor(named: "THREAD_STATE_NONE"), THREAD_STATE_NONE)
        XCTAssertNil(ThreadStateFlavor.flavor(named: "BOGUS"))
        XCTAssertNil(ThreadStateFlavor.flavor(named: ""))
    }
    
    /// A flavor neither SDK defines has no name.
    func testUnknownFlavorHasNoName() {
        XCTAssertNil(ThreadStateFlavor.name(of: 999))
        XCTAssertNil(ThreadStateFlavor.name(of: -1))
    }
}
