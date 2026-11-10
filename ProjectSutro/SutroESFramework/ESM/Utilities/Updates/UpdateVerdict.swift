//
//  UpdateVerdict.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Update verdict
/// Gatekeeper's acceptance of a downloaded update package, and the team that signed it (Security Extension context).
///
/// Read from `spctl --assess --type install --enforce-assessment --raw`, which prints the assessment as a property
/// list on stdout and exits non-zero when the package is rejected. `--enforce-assessment` keeps a disabled Gatekeeper
/// from turning a rejection into an acceptance, and a result that carries an `assessment:authority:override` is
/// refused too. A package is accepted only when:
/// 1. `spctl` exits `0` and `assessment:verdict` is `true`
/// 2. The assessment has no `assessment:authority:override`
/// 3. `assessment:originator` ends in the expected Team ID, such as
///    `Developer ID Installer: Brandon Dalton (4HMJQ7V3SX)`
public struct UpdateVerdict: Equatable, Sendable {
    /// The tool that assesses a package.
    public static let tool = "/usr/sbin/spctl"

    /// The Team ID that signed the accepted package.
    public let teamID: String

    /// The arguments that assess a package.
    ///
    /// - Parameter package: The downloaded package.
    /// - Returns: `spctl`'s arguments.
    public static func arguments(for package: URL) -> [String] {
        ["--assess", "--type", "install", "--enforce-assessment", "-v", "-v", "--raw", package.path]
    }

    /// Accept a package only if Gatekeeper did and the expected team signed it.
    ///
    /// - Parameters:
    ///   - status: `spctl`'s exit status.
    ///   - output: `spctl`'s stdout.
    ///   - team: The Team ID the package must be signed by.
    /// - Throws: ``UpdateError/unreadableAssessment`` for output without a property list,
    ///   ``UpdateError/rejectedByGatekeeper(reason:)`` for a rejection or an override, and
    ///   ``UpdateError/invalidTeamID(found:)`` for a missing or different Team ID.
    public init(status: Int32, output: Data, team: String = SensorXPC.teamID) throws {
        let assessment = try Self.assessment(from: output)
        let authority = assessment["assessment:authority"] as? [String: Any]

        guard status == 0, assessment["assessment:verdict"] as? Bool == true else {
            let source = authority?["assessment:authority:source"] as? String
            throw UpdateError.rejectedByGatekeeper(reason: source ?? "spctl exited with \(status)")
        }
        if let override = authority?["assessment:authority:override"] {
            throw UpdateError.rejectedByGatekeeper(reason: "assessment was overridden (\(override))")
        }
        guard let originator = assessment["assessment:originator"] as? String,
              let teamID = Self.teamID(in: originator) else {
            throw UpdateError.invalidTeamID(found: nil)
        }
        guard teamID == team else { throw UpdateError.invalidTeamID(found: teamID) }
        self.teamID = teamID
    }

    /// Pull the property list out of `spctl --raw` output.
    ///
    /// - Parameter output: `spctl`'s stdout.
    /// - Returns: The assessment dictionary.
    /// - Throws: ``UpdateError/unreadableAssessment`` if there's no property list, or it isn't a dictionary.
    static func assessment(from output: Data) throws -> [String: Any] {
        let text = String(decoding: output, as: UTF8.self)
        guard let start = text.range(of: "<?xml"),
              let end = text.range(of: "</plist>", options: .backwards),
              start.lowerBound < end.upperBound,
              let plist = try? PropertyListSerialization.propertyList(
                from: Data(text[start.lowerBound..<end.upperBound].utf8), format: nil) as? [String: Any] else {
            throw UpdateError.unreadableAssessment
        }
        return plist
    }

    /// The Team ID a signing certificate's name ends in.
    ///
    /// - Parameter originator: Such as `Developer ID Installer: Brandon Dalton (4HMJQ7V3SX)`.
    /// - Returns: Such as `4HMJQ7V3SX`: ten capital letters or digits in parentheses at the very end, else `nil`.
    static func teamID(in originator: String) -> String? {
        guard let match = originator.range(of: #"\(([A-Z0-9]{10})\)$"#, options: .regularExpression) else {
            return nil
        }
        return String(originator[match]).trimmingCharacters(in: CharacterSet(charactersIn: "()"))
    }
}
