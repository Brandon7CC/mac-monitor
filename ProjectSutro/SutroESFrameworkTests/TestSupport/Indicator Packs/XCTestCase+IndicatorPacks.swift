//
//  XCTestCase+IndicatorPacks.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import CryptoKit
@testable import SutroESFramework


// MARK: - Signed indicator packs
/// The signed packs `ProjectSutro/Scripts/Test/generate-indicator-pack-fixtures.sh` wrote, signed by a throwaway
/// certificate authority of team ``packTeam``, and a verifier that trusts only its root.
extension XCTestCase {
    /// The fixtures' Team ID.
    static let packTeam = "ABCDE12345"
    /// The fixtures' current leaf's common name.
    static let packSignerName = "Developer ID Application: Test Signer (ABCDE12345)"
    /// The time the fixture tests' clock says, unless a test sets another.
    static let packClock = packDate("2026-11-15T12:00:00Z")

    /// A time, for a clock or a certificate's dates.
    ///
    /// - Parameter text: The time in ISO 8601, such as `2046-01-01T00:00:00Z`.
    /// - Returns: The time.
    static func packDate(_ text: String) -> Date {
        ISO8601DateFormatter().date(from: text)!
    }

    /// A DER certificate fixture.
    ///
    /// - Parameter name: The fixture's file name, such as `indicator-pack-root.cer`.
    /// - Returns: The certificate.
    /// - Throws: An `XCTest` failure if the fixture is missing or isn't a certificate.
    func certificateFixture(_ name: String) throws -> SecCertificate {
        try XCTUnwrap(SecCertificateCreateWithData(nil, try fixture(name) as CFData), "\(name) isn't a certificate")
    }

    /// The throwaway root the fixtures chain to.
    ///
    /// - Returns: The root.
    /// - Throws: An `XCTest` failure if the fixture is missing.
    func packRoot() throws -> SecCertificate {
        try certificateFixture("indicator-pack-root.cer")
    }

    /// Mac Monitor 3.1's signing chain, as `codesign --extract-certificates` wrote it: its Developer ID Application
    /// certificate, the Developer ID CA, and Apple's root. Public certificates, with no key.
    ///
    /// - Returns: The chain, leaf first.
    /// - Throws: An `XCTest` failure if a fixture is missing.
    func releaseChain() throws -> [SecCertificate] {
        try (0...2).map { try certificateFixture("mac-monitor-3.1-signing-chain-\($0).cer") }
    }

    /// A verifier for the fixtures: it trusts only their root, and requires a Developer ID Application certificate
    /// of a team anchored there, as a release's requirement is anchored at Apple's roots.
    ///
    /// - Parameters:
    ///   - team: The Team ID it requires.
    ///   - clock: The time it says.
    /// - Returns: The verifier.
    /// - Throws: An `XCTest` failure if the root fixture is missing.
    func packVerifier(team: String = XCTestCase.packTeam,
                      clock: Date = XCTestCase.packClock) throws -> IndicatorPackVerifier {
        let root = try packRoot()
        return IndicatorPackVerifier(requirement: .developerID(team: team, anchoredAt: root), anchors: [root],
                                     clock: { clock })
    }

    /// A pack fixture, changed.
    ///
    /// - Parameters:
    ///   - name: The fixture.
    ///   - change: Changes its JSON object.
    /// - Returns: The file's bytes.
    /// - Throws: An `XCTest` failure if the fixture is missing or isn't a JSON object.
    func packFile(_ name: String = "indicator-pack.json",
                  changing change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var object = try fixtureObject(name)
        change(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    }

    /// A pack file of a payload and a signature, as `tools/mmilib/pack.py` writes one.
    ///
    /// - Parameters:
    ///   - payload: The payload's bytes.
    ///   - signature: The signature's bytes.
    /// - Returns: The file's bytes.
    /// - Throws: The error encoding it, which there never is.
    func packFile(payload: Data, signature: Data) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["format": IndicatorPackFile.format,
                                                    "version": IndicatorPackFile.currentVersion,
                                                    "payload": payload.base64EncodedString(),
                                                    "signature": signature.base64EncodedString()])
    }

    /// A pack fixture whose payload or signature bytes are changed.
    ///
    /// - Parameters:
    ///   - key: `payload` or `signature`.
    ///   - change: Changes the bytes.
    /// - Returns: The file's bytes.
    /// - Throws: An `XCTest` failure if the fixture can't be read.
    func packFile(changingBytesOf key: String, _ change: @escaping (inout Data) -> Void) throws -> Data {
        try packFile { object in
            guard var bytes = (object[key] as? String).flatMap({ Data(base64Encoded: $0) }) else { return }
            change(&bytes)
            object[key] = bytes.base64EncodedString()
        }
    }

    /// What verifying a pack throws, if anything.
    ///
    /// - Parameters:
    ///   - file: The pack file's bytes.
    ///   - mode: Installing or loading.
    ///   - verifier: The verifier.
    /// - Returns: The error, or `nil` when the pack was accepted.
    func packRefusal(_ file: Data, _ mode: IndicatorPackVerifier.Mode,
                     by verifier: IndicatorPackVerifier) -> IndicatorPackError? {
        thrown(IndicatorPackError.self) { try verifier.verify(file, mode) }
    }

    /// A certificate's SHA-256, in lowercase hex, as `shasum -a 256` prints it for the DER file.
    ///
    /// - Parameter name: The certificate's fixture.
    /// - Returns: The hash.
    /// - Throws: An `XCTest` failure if the fixture is missing.
    func sha256OfFixture(_ name: String) throws -> String {
        SHA256.hash(data: try fixture(name)).map { String(format: "%02x", $0) }.joined()
    }
}


// MARK: - Packs to install
/// The two releases `generate-indicator-pack-fixtures.sh` signs, `indicator-pack-2.json` and `indicator-pack-3.json`,
/// and packs made here, which no one signed, for what a verified pack does once it's accepted.
///
/// Release 2 has three indicators: "Fixture program ran" at revision 2, "Fixture quarantine removed", and "Fixture
/// program ran too", which is off. Its core identity is the first's, and it retires ``retiredFixtureID``. Release 3
/// changes the first again, to revision 3, and adds an entry that needs Mac Monitor 9.0.0.
extension XCTestCase {
    /// An identity no fixture's indicator has, which the releases retire.
    static let retiredFixtureID = UUID(uuidString: "7A000000-0000-4000-8000-000000000009")!

    /// A signed release fixture: its file, and its payload read.
    ///
    /// - Parameter sequence: 2 or 3.
    /// - Returns: The file's bytes and the pack.
    /// - Throws: An `XCTest` failure if the fixture is missing or isn't a pack.
    func releaseFixture(_ sequence: Int) throws -> (file: Data, pack: IndicatorPack) {
        let file = try fixture("indicator-pack-\(sequence).json")
        return (file, try IndicatorPack.decode(try IndicatorPackFile(file).payload))
    }

    /// The indicators a build older than release 2 links in: release 2's first as it was at revision 1, with another
    /// predicate, its second exactly as release 2 has it, and "Fixture dropped", which no release has.
    ///
    /// - Returns: The three, in that order.
    /// - Throws: An `XCTest` failure if the fixture is missing.
    func linkedFixtures() throws -> [Indicator] {
        let released = try releaseFixture(2).pack.indicators
        var ran = released[0]
        ran.rule = .event(#"event.exec != nil AND process.executable.path == "/usr/bin/old""#)
        ran.revision = 1
        let dropped = Indicator(id: UUID(uuidString: "7A000000-0000-4000-8000-000000000003")!, name: "Fixture dropped",
                                description: "No release has it.", symbol: "trash", color: .gray,
                                predicate: #"event.exec != nil AND process.executable.path == "/usr/bin/dropped""#)
        return [ran, released[1], dropped]
    }

    /// A pack's payload, as the indicators repository builds one.
    ///
    /// - Parameters:
    ///   - sequence: Which release it is.
    ///   - indicators: Its indicators.
    ///   - core: The identities it says Mac Monitor's code depends on.
    ///   - retired: The identities it says are never used again.
    ///   - change: Changes its JSON object.
    /// - Returns: The payload's bytes.
    /// - Throws: The error encoding it.
    func packPayload(sequence: Int, _ indicators: [Indicator], core: [UUID] = [], retired: [UUID] = [],
                     changing change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var object: [String: Any] = [
            "format": IndicatorExchange.format,
            "version": 2,
            "pack": ["sequence": sequence, "published": "2026-11-16T00:00:00Z",
                     "commit": String(repeating: "a", count: 40), "min_engine": "3.2.0",
                     "core": core.map(\.uuidString), "retired": retired.map(\.uuidString)],
            "indicators": try JSONSerialization.jsonObject(with: try JSONEncoder().encode(indicators)),
        ]
        change(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    /// A payload as a verifier would hand it over, had someone signed it.
    ///
    /// - Parameter payload: The payload's bytes.
    /// - Returns: It, with the fixtures' signer.
    func verified(_ payload: Data) -> VerifiedIndicatorPack {
        VerifiedIndicatorPack(payload: payload,
                              signer: IndicatorPackSigner(teamID: Self.packTeam, commonName: Self.packSignerName,
                                                          certificateSHA256: "", expires: .distantFuture))
    }
}


// MARK: - Installing into a set
extension SavedIndicatorSet {
    /// Check or install a payload as if its signature had been accepted, as a caller that may change the set.
    ///
    /// - Parameters:
    ///   - payload: The pack's payload.
    ///   - installs: Install it, or only say what installing it would change?
    ///   - file: The pack's file to keep: the payload's bytes unless given, which no later load accepts.
    /// - Returns: The reply.
    func take(_ payload: VerifiedIndicatorPack, installs: Bool = true, file: Data? = nil) -> IndicatorReply {
        let reply = queue.sync {
            answer(to: PackRequest(file: file ?? payload.payload, installs: installs), .success(payload),
                   access: .write, caller: "Test")
        }
        return IndicatorReply.decode(reply) ?? IndicatorReply(status: .unsupported, indicators: [])
    }
}

