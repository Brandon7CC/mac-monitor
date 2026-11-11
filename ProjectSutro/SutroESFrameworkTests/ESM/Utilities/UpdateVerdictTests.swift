//
//  UpdateVerdictTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Gatekeeper's verdict on an update package
/// Pins how the Security Extension reads `spctl --raw` before it installs a package as root: only an accepted,
/// unoverridden assessment of a package signed by Swiftly Detecting's team passes, and output it can't read never
/// does.
///
/// `spctl-notarized.txt` is `spctl`'s stdout for Mac Monitor's notarized release package (exit 0), and
/// `spctl-no-usable-signature.txt` for an unsigned `pkgbuild` package (exit 3), both recorded on macOS 27. The other
/// cases change one key of those.
final class UpdateVerdictTests: XCTestCase {
    /// A recorded assessment, with one change, as `spctl` prints it.
    ///
    /// - Parameters:
    ///   - name: The fixture.
    ///   - change: Changes the assessment.
    /// - Returns: The output.
    /// - Throws: If the fixture is missing or isn't a property list.
    private func assessment(_ name: String = "spctl-notarized.txt",
                            changing change: (inout [String: Any]) -> Void) throws -> Data {
        let recorded = try fixture(name)
        var plist = try XCTUnwrap(try PropertyListSerialization.propertyList(from: recorded, format: nil)
                                  as? [String: Any])
        change(&plist)
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    /// The recorded notarized assessment with another originator.
    ///
    /// - Parameter originator: The signing certificate's name, or `nil` for none.
    /// - Returns: The output.
    /// - Throws: If the fixture can't be read.
    private func signed(by originator: String?) throws -> Data {
        try assessment { $0["assessment:originator"] = originator }
    }

    /// What reading an assessment throws, if anything.
    ///
    /// - Parameters:
    ///   - status: `spctl`'s exit status.
    ///   - output: `spctl`'s stdout.
    /// - Returns: The error, or `nil` if the package was accepted.
    private func refusal(_ status: Int32, _ output: Data) -> UpdateError? {
        thrown(UpdateError.self) { try UpdateVerdict(status: status, output: output) }
    }

    /// Mac Monitor's notarized release package is accepted, and its team is ours.
    func testTheNotarizedReleaseIsAccepted() throws {
        let verdict = try UpdateVerdict(status: 0, output: try fixture("spctl-notarized.txt"))
        XCTAssertEqual(verdict.teamID, "4HMJQ7V3SX")
        XCTAssertEqual(verdict.teamID, SensorXPC.teamID)
    }

    /// A package Gatekeeper rejects, or one `spctl` exits non-zero for, is refused with Gatekeeper's reason, however
    /// the other of the two reads. A verdict that's missing or isn't a Boolean `true` is a rejection.
    func testARejectionIsRefused() throws {
        let unsigned = try fixture("spctl-no-usable-signature.txt")
        let accepted = try fixture("spctl-notarized.txt")
        XCTAssertEqual(refusal(3, unsigned), .rejectedByGatekeeper(reason: "no usable signature"))
        XCTAssertEqual(refusal(0, unsigned), .rejectedByGatekeeper(reason: "no usable signature"))
        XCTAssertEqual(refusal(3, accepted), .rejectedByGatekeeper(reason: "Notarized Developer ID"))
        XCTAssertEqual(refusal(0, try assessment { $0["assessment:verdict"] = nil }),
                       .rejectedByGatekeeper(reason: "Notarized Developer ID"))
        XCTAssertEqual(refusal(0, try assessment { $0["assessment:verdict"] = "true" }),
                       .rejectedByGatekeeper(reason: "Notarized Developer ID"))
        let bare = try assessment { $0["assessment:authority"] = nil; $0["assessment:verdict"] = false }
        XCTAssertEqual(refusal(1, bare), .rejectedByGatekeeper(reason: "spctl exited with 1"))
    }

    /// An accepted assessment Gatekeeper's settings overrode is refused, whatever the override says.
    func testAnOverrideIsRefused() throws {
        let overrides: [Any] = ["security disabled", "user approved", 1]
        for override in overrides {
            let output = try assessment { plist in
                var authority = plist["assessment:authority"] as? [String: Any] ?? [:]
                authority["assessment:authority:override"] = override
                plist["assessment:authority"] = authority
            }
            XCTAssertEqual(refusal(0, output), .rejectedByGatekeeper(reason: "assessment was overridden (\(override))"))
        }
    }

    /// Only a certificate whose name ends in our Team ID, ten capitals or digits in parentheses, passes. Another team,
    /// no originator, or a name that only contains our Team ID is refused.
    func testOnlyOurTeamIsAccepted() throws {
        let cases: [(originator: String?, found: String?)] = [
            ("Developer ID Installer: Example Corp (ABCDE12345)", "ABCDE12345"),
            ("Developer ID Installer: Mallory (4HMJQ7V3SX) (ABCDE12345)", "ABCDE12345"),
            (nil, nil),
            ("Developer ID Installer: Brandon Dalton", nil),
            ("Developer ID Installer: Brandon Dalton (4hmjq7v3sx)", nil),
            ("Developer ID Installer: Brandon Dalton (4HMJQ7V3S)", nil),
            ("Developer ID Installer: Brandon Dalton (44HMJQ7V3SX)", nil),
            ("Developer ID Installer: Brandon Dalton (4HMJQ7V3SX) ", nil),
            ("Developer ID Installer: Brandon Dalton (4HMJQ7V3SX).", nil),
        ]
        for (originator, found) in cases {
            XCTAssertEqual(refusal(0, try signed(by: originator)), .invalidTeamID(found: found), originator ?? "none")
        }
        let other = try signed(by: "Developer ID Installer: Example Corp (ABCDE12345)")
        XCTAssertEqual(try UpdateVerdict(status: 0, output: other, team: "ABCDE12345").teamID, "ABCDE12345")
    }

    /// The property list is found among anything else `spctl` prints. Output without one, or with one that doesn't
    /// read or isn't a dictionary, is unreadable, before the exit status is looked at.
    func testTheAssessmentMustRead() throws {
        let recorded = String(decoding: try fixture("spctl-notarized.txt"), as: UTF8.self)
        let noisy = "spctl: assessing\n" + recorded + "/private/tmp/MacMonitorUpdate.pkg: accepted\n"
        XCTAssertEqual(try UpdateVerdict(status: 0, output: Data(noisy.utf8)).teamID, "4HMJQ7V3SX")

        let array = try PropertyListSerialization.data(fromPropertyList: ["assessment:verdict"], format: .xml,
                                                       options: 0)
        let unreadable = [
            Data(),
            Data("/private/tmp/MacMonitorUpdate.pkg: accepted\n".utf8),
            Data(recorded.replacingOccurrences(of: "</plist>", with: "").utf8),
            Data(recorded.replacingOccurrences(of: "<?xml", with: "<?xm").utf8),
            Data(recorded.replacingOccurrences(of: "</dict>\n</plist>", with: "</plist>").utf8),
            Data("</plist><?xml".utf8),
            array,
        ]
        for output in unreadable {
            XCTAssertEqual(refusal(0, output), .unreadableAssessment, String(decoding: output, as: UTF8.self))
            XCTAssertEqual(refusal(3, output), .unreadableAssessment)
        }
    }

    /// `spctl` assesses the package for installing, with assessments enforced, and prints a property list.
    func testTheCommandEnforcesAssessment() {
        let package = URL(fileURLWithPath: "/private/tmp/work/MacMonitorUpdate.pkg")
        XCTAssertEqual(UpdateVerdict.tool, "/usr/sbin/spctl")
        XCTAssertEqual(UpdateVerdict.arguments(for: package),
                       ["--assess", "--type", "install", "--enforce-assessment", "-v", "-v", "--raw", package.path])
    }

    /// Each refusal tells Mac Monitor which step failed, and logs a reason.
    func testErrorsSayWhichStepFailed() {
        let cases: [(UpdateError, UpdateFailure)] = [
            (.releaseLookupFailed, .download),
            (.insecureDownload(URL(string: "http://example.com/a.pkg")!), .download),
            (.downloadFailed, .download),
            (.noNewerRelease, .noNewerRelease),
            (.unreadableAssessment, .gatekeeper),
            (.rejectedByGatekeeper(reason: "no usable signature"), .gatekeeper),
            (.invalidTeamID(found: "ABCDE12345"), .teamID),
            (.invalidTeamID(found: nil), .teamID),
            (.installFailed(exitCode: 1, errorLog: "failed"), .installer),
        ]
        for (error, failure) in cases {
            XCTAssertEqual(error.failure, failure, "\(error)")
            XCTAssertFalse(error.localizedDescription.isEmpty)
        }
        XCTAssertEqual(UpdateError.invalidTeamID(found: nil).localizedDescription,
                       "The Team ID of the package was invalid. Found: none, expected: 4HMJQ7V3SX")
    }
}
