//
//  SensorXPCRequirementTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import Security
@testable import SutroESFramework


// MARK: - Code signing requirements
/// Pins the requirements the Security Extension's listener and each connection enforce: they compile, in both the
/// Developer ID and the Community variant, and the listener admits Mac Monitor and `macmonitor` and no one else.
final class SensorXPCRequirementTests: XCTestCase {
    /// The signing identifiers of the three programs.
    private let identifiers = ["com.swiftlydetecting.agent", "com.swiftlydetecting.agent.cli",
                               "com.swiftlydetecting.agent.securityextension"]
    
    /// Does a file's code signature satisfy a requirement?
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - requirement: A requirement string.
    /// - Returns: `true` if the signature is valid and satisfies it.
    private func signature(of path: String, satisfies requirement: String) -> Bool {
        var code: SecStaticCode?, compiled: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess, let compiled
        else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), compiled) == errSecSuccess
    }
    
    /// A copy of `/usr/bin/true`, ad-hoc signed with an identifier, as a Community build signs its programs. Removed
    /// when the test ends.
    ///
    /// - Parameter identifier: The signing identifier.
    /// - Returns: The copy's path.
    /// - Throws: If it can't be copied or `codesign` can't be run.
    private func adHocCopy(signedAs identifier: String) throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SensorXPCRequirement-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let copy = directory.appendingPathComponent("program").path
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: copy)
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--force", "--sign", "-", "--identifier", identifier, copy]
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        XCTAssertEqual(codesign.terminationStatus, 0, identifier)
        return copy
    }
    
    /// Does the Security framework compile a requirement string?
    ///
    /// - Parameter requirement: The requirement string.
    /// - Returns: `true` if `SecRequirementCreateWithString` accepts it.
    private func compiles(_ requirement: String) -> Bool {
        var compiled: SecRequirement?
        let status = SecRequirementCreateWithString(requirement as CFString, [], &compiled)
        return status == errSecSuccess && compiled != nil
    }
    
    /// Each identifier's requirement compiles in both variants, and so does either-of for the listener.
    func testEveryVariantCompiles() {
        for variant in [SensorXPC.developerIDRequirement(for:), SensorXPC.communityRequirement(for:)] {
            identifiers.forEach { XCTAssertTrue(compiles(variant($0)), variant($0)) }
            let listener = SensorXPC.either(variant(identifiers[0]), variant(identifiers[1]))
            XCTAssertTrue(compiles(listener), listener)
        }
        XCTAssertFalse(compiles("identifier \"unterminated"))
    }
    
    /// Evaluated against signed code, the listener's requirement admits a program signed as Mac Monitor or as
    /// `macmonitor`, and nothing else: not one signed as the Security Extension, and not an Apple tool. Ad-hoc copies
    /// stand in for a Community build's programs, which only the Community variant admits.
    ///
    /// - Throws: If a copy can't be made.
    func testTheListenerAdmitsMacMonitorAndTheCommandLineToolOnly() throws {
        let copies = try identifiers.map { try adHocCopy(signedAs: $0) }
        let community = SensorXPC.either(SensorXPC.communityRequirement(for: identifiers[0]),
                                         SensorXPC.communityRequirement(for: identifiers[1]))
        let developerID = SensorXPC.either(SensorXPC.developerIDRequirement(for: identifiers[0]),
                                           SensorXPC.developerIDRequirement(for: identifiers[1]))
        XCTAssertEqual(copies.map { signature(of: $0, satisfies: community) }, [true, true, false])
        XCTAssertEqual(copies.map { signature(of: $0, satisfies: developerID) }, [false, false, false])
        XCTAssertTrue([community, developerID].contains(SensorXPC.listenerRequirement))
        for requirement in [community, developerID] {
            XCTAssertFalse(signature(of: "/bin/ls", satisfies: requirement), requirement)
        }
    }
    
    /// The Developer ID variant is the requirement 2.1 shipped, byte for byte: Developer ID certificates and the
    /// team.
    func testTheDeveloperIDVariantIsUnchanged() {
        XCTAssertEqual(SensorXPC.developerIDRequirement(for: "com.swiftlydetecting.agent.cli"), """
            anchor apple generic and identifier "com.swiftlydetecting.agent.cli" and certificate \
            1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
            certificate leaf[subject.OU] = "4HMJQ7V3SX"
            """)
    }
}
