//
//  IndicatorPackVerifyCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Verifying a pack
/// Pins `macmonitor indicators pack verify`: a signed pack checked as the Security Extension checks one before
/// installing it, what it says about one it would install, why it refuses one, and its command line. The signed
/// fixtures are the verifier's, made with a throwaway chain (``XCTestCase/packVerifier(team:clock:)``).
final class IndicatorPackVerifyCommandTests: XCTestCase {
    /// Verify a fixture with the test chain.
    ///
    /// - Parameter name: The signed pack fixture.
    /// - Returns: What the command came to, and what it wrote.
    private func verify(_ name: String) throws -> (result: Result<Void, CommandLineFailure>, output: String) {
        let output = Captured()
        let result = IndicatorPackVerifyCommand.run(path: try fixtureURL(name).path, output: output,
                                                    verifier: try packVerifier())
        return (result, output.text)
    }

    /// Each refusal exits 65 and says why: an expired certificate, a signer that isn't Developer ID, and a payload
    /// that isn't a pack. A file that can't be read exits 66. None writes anything.
    func testRefusals() throws {
        let cases: [(String, String)] = [
            ("indicator-pack-expired.json", "Mac Monitor wouldn't install"),
            ("indicator-pack-not-developer-id.json", "Mac Monitor wouldn't install"),
            ("indicator-pack.json", "is signed, but its payload isn't a pack Mac Monitor would install. It has no "
                + "indicators."),
        ]
        for (name, words) in cases {
            let (result, output) = try verify(name)
            guard case .failure(let failure) = result else { return XCTFail("\(name) verified") }
            XCTAssertEqual(failure.exit, .dataError, name)
            XCTAssertTrue(failure.message.contains(words), "\(failure.message) should say \(words)")
            XCTAssertEqual(output, "", name)
        }
        let missing = IndicatorPackVerifyCommand.run(path: "/nonexistent/pack.json", output: Captured(),
                                                     verifier: try packVerifier())
        guard case .failure(let failure) = missing else { return XCTFail("A missing file verified") }
        XCTAssertEqual(failure.exit, .noInput)
    }

    /// A pack it would install says who signed it, when the certificate expires, and what the pack holds.
    func testWhatAPackHolds() throws {
        let sequence = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: Data(IndicatorSequenceTests.packEntry.utf8)) as? [String: Any])
        let payload = try JSONSerialization.data(withJSONObject: [
            "format": IndicatorExchange.format, "version": 2,
            "pack": ["sequence": 1, "published": "2026-11-15T09:35:16Z", "commit": "f8911d21087230825953cbe4e948f78f",
                     "min_engine": "3.2.0", "core": [sequence["id"]], "retired": []],
            "indicators": [sequence],
        ])
        let pack = try IndicatorPack.decode(payload)
        let signer = IndicatorPackSigner(teamID: "4HMJQ7V3SX",
                                         commonName: "Developer ID Application: Test (4HMJQ7V3SX)",
                                         certificateSHA256: "ab12",
                                         expires: XCTestCase.packDate("2027-02-01T12:00:00Z"))
        let lines = IndicatorPackVerifyCommand.text(signer: signer, pack: pack).split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 4)
        XCTAssertEqual(lines[0], "Signed by “Developer ID Application: Test (4HMJQ7V3SX)”, Team ID 4HMJQ7V3SX.")
        XCTAssertTrue(lines[1].hasPrefix("Its certificate's SHA-256 is ab12, and it expires on "), lines[1])
        XCTAssertEqual(lines[2], "Pack 1, built from commit f8911d2 on 2026-11-15T09:35:16Z, for Mac Monitor 3.2.0 or "
                       + "later.")
        XCTAssertEqual(lines[3], "1 indicator, 1 of them a sequence. 1 core identity and 0 retired.")
    }

    /// `indicators pack verify FILE` parses, needs one file and no options, and needs neither root nor the Security
    /// Extension.
    func testCommandLine() throws {
        let parsed = try CommandLineParser.parse(["indicators", "pack", "verify", "pack.json"])
        XCTAssertEqual(parsed, .indicators(.pack(.verify("pack.json"))))
        XCTAssertFalse(parsed.requiresRoot)
        for arguments in [["indicators", "pack"], ["indicators", "pack", "verfy", "a.json"],
                          ["indicators", "pack", "verify"], ["indicators", "pack", "verify", "a.json", "b.json"],
                          ["indicators", "pack", "verify", "a.json", "--json"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(arguments), arguments.joined(separator: " "))
        }
    }
}


// MARK: - Captured output
/// Standard output a test reads back.
private final class Captured: StreamOutput {
    /// What was written, as text.
    private(set) var text = ""

    /// - Parameter data: The bytes.
    func write(_ data: Data) throws {
        text += String(decoding: data, as: UTF8.self)
    }
}
