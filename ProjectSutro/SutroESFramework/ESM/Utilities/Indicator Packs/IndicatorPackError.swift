//
//  IndicatorPackError.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Indicator pack error
/// Why a signed indicator pack wasn't accepted (``IndicatorPackVerifier``). Its description is a sentence the user
/// reads, and ``hint`` says what to do when this Mac's clock looks wrong.
public enum IndicatorPackError: LocalizedError, Equatable {
    /// The file is larger than ``IndicatorLimits/maxFileBytes``: its size in bytes.
    case tooLarge(bytes: Int)
    /// The file isn't JSON with a format and a version, or its payload or signature isn't base64.
    case unreadable
    /// The file says it's something other than a signed indicator pack: what it says.
    case unknownFormat(String)
    /// The file is a version this build doesn't read: its version.
    case unsupportedVersion(Int)
    /// The file has no signature.
    case unsigned
    /// The signature isn't a CMS message `CMSDecoder` can read.
    case unreadableSignature
    /// The signature carries content of its own, so it doesn't sign the payload.
    case contentInSignature
    /// The signature has this many signers, not exactly one.
    case signers(Int)
    /// The signature doesn't verify over the payload's bytes.
    case signatureDoesNotVerify
    /// This Mac can't evaluate a code signing requirement, so it can't say who signed the pack.
    case cannotCheckSigner
    /// The signer's certificate isn't a Developer ID Application certificate from the expected anchor.
    case notDeveloperID
    /// The signer's certificate is of another team: the Team ID it has, if any, and the one required.
    case wrongTeam(found: String?, expected: String)
    /// A certificate in the chain expired: its common name, when, and the time this Mac's clock said.
    case expired(certificate: String, on: Date, clock: Date)
    /// A certificate in the chain isn't valid yet: its common name, from when, and the time this Mac's clock said.
    case notYetValid(certificate: String, from: Date, clock: Date)
    /// The signer's certificate was revoked.
    case revoked
    /// The chain isn't trusted, for the reason SecTrust gave.
    case untrusted(reason: String)

    /// The first day this Mac's clock could plausibly say: the day this check was written. A Mac whose clock reads
    /// earlier is wrong, whatever the certificate.
    public static let earliestPlausibleDate = Date(timeIntervalSince1970: 1_794_700_800)

    /// What went wrong, as the user reads it.
    public var errorDescription: String? {
        switch self {
        case .tooLarge(let bytes):
            return "The pack is \(bytes) bytes, larger than 4 MiB."
        case .unreadable:
            return "The file isn't an indicator pack: it isn't JSON with a format, a version, a payload and a "
                + "signature."
        case .unknownFormat(let format):
            return "The file is “\(format)”, not a signed indicator pack."
        case .unsupportedVersion(let version) where version > IndicatorPackFile.currentVersion:
            return "The pack is version \(version), from a newer Mac Monitor."
        case .unsupportedVersion(let version):
            return "The pack is version \(version), which no Mac Monitor reads."
        case .unsigned:
            return "The pack isn't signed."
        case .unreadableSignature:
            return "The pack's signature can't be read."
        case .contentInSignature:
            return "The pack's signature signs content of its own, not the pack."
        case .signers(0):
            return "The pack's signature has no signer."
        case .signers(let count):
            return "The pack has \(count) signers, and must have exactly one."
        case .signatureDoesNotVerify:
            return "The pack's signature doesn't verify, so the pack changed after it was signed."
        case .cannotCheckSigner:
            return "This Mac can't check who signed the pack."
        case .notDeveloperID:
            return "It isn't signed with a Developer ID Application certificate from Apple."
        case .wrongTeam(let found?, let expected):
            return "It's signed by Team ID \(found), not \(expected)."
        case .wrongTeam(nil, let expected):
            return "It's signed by a certificate with no Team ID, not by \(expected)."
        case .expired(let certificate, let date, _):
            return "The certificate “\(certificate)” expired on \(Self.day(date))."
        case .notYetValid(let certificate, let date, _):
            return "The certificate “\(certificate)” isn't valid until \(Self.day(date))."
        case .revoked:
            return "The pack's certificate was revoked."
        case .untrusted(let reason):
            return "The pack's certificate isn't trusted: \(reason)."
        }
    }

    /// Does this Mac's clock look wrong? A certificate that isn't valid yet means the clock is behind, since the
    /// certificate was issued before it was found here. An expired one alone doesn't say, unless the clock reads
    /// before ``earliestPlausibleDate``.
    public var clockLooksWrong: Bool {
        switch self {
        case .notYetValid: return true
        case .expired(_, _, let clock): return clock < Self.earliestPlausibleDate
        default: return false
        }
    }

    /// What to do when this Mac's clock looks wrong (``clockLooksWrong``), else `nil`.
    public var hint: String? {
        switch self {
        case .expired(_, _, let clock) where clockLooksWrong, .notYetValid(_, _, let clock) where clockLooksWrong:
            return "This Mac's clock says it's \(Self.day(clock)). If that's wrong, set the date and time in System "
                + "Settings, then try again."
        default:
            return nil
        }
    }

    /// The hint, where Foundation looks for one.
    public var recoverySuggestion: String? { hint }

    /// The description and the hint together, as one message.
    public var message: String {
        [errorDescription, hint].compactMap { $0 }.joined(separator: " ")
    }

    /// A date as the messages say it, such as "February 1, 2027", in this Mac's time zone.
    ///
    /// - Parameter date: The date.
    /// - Returns: The day.
    static func day(_ date: Date) -> String {
        date.formatted(date: .long, time: .omitted)
    }
}
