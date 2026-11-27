//
//  EnvironmentVariableTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Environment variables
/// Pins how an exec's environment is split into names and values and filtered, as Event Facts' Environment table
/// shows it.
final class EnvironmentVariableTests: XCTestCase {
    /// A variable splits at its first "=", and the value keeps the rest.
    func testSplitsAtTheFirstEquals() {
        let variable = EnvironmentVariable("OPTS=a=1,b=2", at: 0)
        XCTAssertEqual(variable.name, "OPTS")
        XCTAssertEqual(variable.value, "a=1,b=2")
        XCTAssertEqual(variable.variable, "OPTS=a=1,b=2")
    }

    /// A variable without "=" is a name with an empty value, and an empty name or value stays empty.
    func testMissingParts() {
        XCTAssertEqual(EnvironmentVariable("FLAG", at: 0).name, "FLAG")
        XCTAssertEqual(EnvironmentVariable("FLAG", at: 0).value, "")
        XCTAssertEqual(EnvironmentVariable("EMPTY=", at: 0).name, "EMPTY")
        XCTAssertEqual(EnvironmentVariable("EMPTY=", at: 0).value, "")
        XCTAssertEqual(EnvironmentVariable("=value", at: 0).name, "")
        XCTAssertEqual(EnvironmentVariable("=value", at: 0).value, "value")
    }

    /// A variable splits at its first "=" scalar, as the kernel splits at its first "=" byte. A combining mark or a
    /// variation selector after the "=" makes one character of the two, and doesn't move the split.
    func testSplitsAtTheFirstEqualsScalar() {
        let combining = EnvironmentVariable("NAME=\u{301}x=y", at: 0)
        XCTAssertEqual(combining.name, "NAME")
        XCTAssertEqual(combining.value, "\u{301}x=y")
        let selector = EnvironmentVariable("NAME=\u{FE0F}v", at: 0)
        XCTAssertEqual(selector.name, "NAME")
        XCTAssertEqual(selector.value, "\u{FE0F}v")
    }

    /// Duplicate names are kept, in order, each identified by its position.
    func testDuplicateNamesAreKept() {
        let variables = EnvironmentVariable.variables(in: ["A=1", "B=2", "A=3"])
        XCTAssertEqual(variables.map(\.id), [0, 1, 2])
        XCTAssertEqual(variables.map(\.name), ["A", "B", "A"])
        XCTAssertEqual(variables.map(\.value), ["1", "2", "3"])
    }

    /// The filter matches a name or a value, ignoring case.
    func testMatchingNameOrValueIgnoringCase() {
        let variables = EnvironmentVariable.variables(in: ["PATH=/usr/bin", "HOME=/Users/test", "SHELL=/bin/zsh"])
        XCTAssertEqual(EnvironmentVariable.matching("path", in: variables).map(\.name), ["PATH"])
        XCTAssertEqual(EnvironmentVariable.matching("USERS", in: variables).map(\.name), ["HOME"])
        XCTAssertEqual(EnvironmentVariable.matching("bin", in: variables).map(\.name), ["PATH", "SHELL"])
        XCTAssertEqual(EnvironmentVariable.matching("nothing", in: variables), [])
    }

    /// Empty or blank text matches every variable, and the text's surrounding whitespace is ignored.
    func testBlankTextMatchesEveryVariable() {
        let variables = EnvironmentVariable.variables(in: ["A=1", "B=2"])
        XCTAssertEqual(EnvironmentVariable.matching("", in: variables), variables)
        XCTAssertEqual(EnvironmentVariable.matching("  \n", in: variables), variables)
        XCTAssertEqual(EnvironmentVariable.matching(" b ", in: variables).map(\.name), ["B"])
    }

    /// A stored exec event's environment splits in its own order, as Event Facts read it.
    func testStoredExecEvent() throws {
        let env = ["PATH=/usr/bin:/bin", "XPC_SERVICE_NAME=com.example.agent", "PATH=/opt/bin"]
        let message = try importRecord(try esloggerExec(parent: (1, 1), env: env))
        let variables = withStoredEvent(message) { EnvironmentVariable.variables(in: $0.event.exec?.env ?? []) }
        XCTAssertEqual(variables.map(\.variable), env)
        XCTAssertEqual(variables.map(\.name), ["PATH", "XPC_SERVICE_NAME", "PATH"])
    }
}
