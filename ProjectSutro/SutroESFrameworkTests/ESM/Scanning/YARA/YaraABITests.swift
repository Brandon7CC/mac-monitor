//
//  YaraABITests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/24/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The libyara layout
/// Pins how the libyara layout is read from the runtime's encodings. The encodings are the ones the macOS 13.6 and
/// 27.2 VMs recorded for `initFromYARA:` and `XPMalwareEvaluation`'s `_rules`, so the macOS 13 layout is checked here
/// though XCTest can't run there.
final class YaraABITests: XCTestCase {
    /// macOS 13.6's YARA 3.11: per-thread flags, so the identifier is at 136.
    static let rule13 = "^{YR_RULE=i[32i](?=*q)(?=*q)(?=^{YR_META}q)(?=^{YR_STRING}q)(?=^{YR_NAMESPACE}q)iq[32q]}"
    static let rules13 = "^{YR_RULES=[4C]*{_opaque_pthread_mutex_t=q[56c]}^{_YR_ARENA}^{YR_RULE}" +
        "^{YR_EXTERNAL_VARIABLE}^I^{YR_AC_MATCH_TABLE_ENTRY}IQ}"
    /// macOS 27.2's YARA 4.1: two 32-bit fields, so the identifier is at 8.
    static let rule27 = "^{YR_RULE=ii(?=*{YR_ARENA_REF=II})(?=*{YR_ARENA_REF=II})(?=^{YR_META}{YR_ARENA_REF=II})" +
        "(?=^{YR_STRING}{YR_ARENA_REF=II})(?=^{YR_NAMESPACE}{YR_ARENA_REF=II})}"
    static let rules27 = "^{YR_RULES=^{YR_ARENA}(?=^{YR_RULE}^{YR_RULE})(?=^{YR_STRING}^{YR_STRING})" +
        "(?=^{YR_EXTERNAL_VARIABLE}^{YR_EXTERNAL_VARIABLE})^I^{YR_AC_MATCH}^I*III}"
    /// YARA 4.5's rule, as its header declares it: two more 32-bit fields before the identifier.
    static let rule45 = "^{YR_RULE=iiII(?=*{YR_ARENA_REF=II})(?=*{YR_ARENA_REF=II})(?=^{YR_META}{YR_ARENA_REF=II})" +
        "(?=^{YR_STRING}{YR_ARENA_REF=II})(?=^{YR_NAMESPACE}{YR_ARENA_REF=II})}"

    /// macOS 13's layout is YARA 3 with the identifier at 136, as the lab's scans of it read.
    func testMacOS13IsYara3() throws {
        let abi = try YaraABI.read(ruleEncoding: Self.rule13, ruleClassName: "YaraRule", rulesEncoding: Self.rules13)
        XCTAssertEqual(abi, YaraABI(generation: .yara3, identifierOffset: 136))
    }

    /// macOS 27's layout is YARA 4 with the identifier at 8.
    func testMacOS27IsYara4() throws {
        let abi = try YaraABI.read(ruleEncoding: Self.rule27, ruleClassName: "YARARule", rulesEncoding: Self.rules27)
        XCTAssertEqual(abi, YaraABI(generation: .yara4, identifierOffset: 8))
    }

    /// A YARA 4.5 layout moves the identifier to 16, and is still read, without `_rules`.
    func testYara45MovesTheIdentifier() throws {
        let abi = try YaraABI.read(ruleEncoding: Self.rule45, ruleClassName: "YARARule", rulesEncoding: nil)
        XCTAssertEqual(abi, YaraABI(generation: .yara4, identifierOffset: 16))
    }

    /// A rule class that doesn't go with the layout makes scanning unavailable.
    func testTheRuleClassMustMatch() {
        XCTAssertThrowsError(try YaraABI.read(ruleEncoding: Self.rule13, ruleClassName: "YARARule",
                                              rulesEncoding: nil))
        XCTAssertThrowsError(try YaraABI.read(ruleEncoding: Self.rule27, ruleClassName: "YaraRule",
                                              rulesEncoding: nil))
    }

    /// A rule set layout of the other generation makes scanning unavailable.
    func testTheRuleSetMustAgree() {
        XCTAssertThrowsError(try YaraABI.read(ruleEncoding: Self.rule27, ruleClassName: "YARARule",
                                              rulesEncoding: Self.rules13))
    }

    /// Any other shape is refused rather than guessed: no identifier, an object before it, or no `YR_RULE` at all.
    func testUnknownLayoutsAreRefused() {
        for encoding in ["^{YR_RULE=iiq}", "^{YR_RULE=i@(?=*q)}", "^{YR_RULES=ii}", "", "^{YR_RULE=(?=*q)}"] {
            XCTAssertThrowsError(try YaraABI.read(ruleEncoding: encoding, ruleClassName: "YARARule",
                                                  rulesEncoding: nil), encoding) { error in
                guard case YaraUnavailable.unknownLayout = error else { return XCTFail("\(error)") }
            }
        }
    }

    /// The rule set encodings name their generations, and anything else names none.
    func testRuleSetGenerations() {
        XCTAssertEqual(YaraABI.generation(ofRules: Self.rules13), .yara3)
        XCTAssertEqual(YaraABI.generation(ofRules: Self.rules27), .yara4)
        XCTAssertNil(YaraABI.generation(ofRules: "^{YR_RULES=q}"))
    }
}
