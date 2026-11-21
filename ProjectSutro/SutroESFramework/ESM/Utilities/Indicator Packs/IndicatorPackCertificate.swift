//
//  IndicatorPackCertificate.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import Security
import CryptoKit


// MARK: - Indicator pack certificate
/// What the pack verifier reads from a certificate: its names, the dates it's valid between, and its SHA-256.
///
/// Read with `SecCertificateCopyValues`, which every macOS this framework runs on has
/// (`SecCertificateCopyNotValidAfterDate` needs macOS 15).
struct IndicatorPackCertificate {
    /// The certificate.
    let certificate: SecCertificate
    /// The subject's common name, or its summary when it has none.
    let commonName: String
    /// The subject's first organizational unit: a Developer ID certificate's Team ID. `nil` when it has none.
    let organizationalUnit: String?
    /// When the certificate becomes valid: when it was issued.
    let notBefore: Date
    /// When the certificate expires.
    let notAfter: Date

    /// Read a certificate.
    ///
    /// - Parameter certificate: The certificate.
    /// - Returns: Its fields, or `nil` when its validity dates can't be read.
    init?(_ certificate: SecCertificate) {
        let keys = [kSecOIDX509V1SubjectName, kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter]
        guard let values = SecCertificateCopyValues(certificate, keys as CFArray, nil) as? [String: Any],
              let notBefore = Self.date(values[kSecOIDX509V1ValidityNotBefore as String]),
              let notAfter = Self.date(values[kSecOIDX509V1ValidityNotAfter as String]) else { return nil }
        let subject = Self.value(values[kSecOIDX509V1SubjectName as String]) as? [[String: Any]] ?? []
        let name = { (oid: CFString) in
            subject.first { $0[kSecPropertyKeyLabel as String] as? String == oid as String }
                .flatMap { $0[kSecPropertyKeyValue as String] as? String }
        }
        self.certificate = certificate
        self.notBefore = notBefore
        self.notAfter = notAfter
        organizationalUnit = name(kSecOIDOrganizationalUnitName)
        commonName = name(kSecOIDCommonName) ?? SecCertificateCopySubjectSummary(certificate) as String? ?? ""
    }

    /// The certificate's SHA-256, in lowercase hex, as `shasum -a 256` prints it for the DER file.
    var sha256: String {
        SHA256.hash(data: SecCertificateCopyData(certificate) as Data).withUnsafeBytes {
            ESLogger.hex(bytes: $0, uppercase: false)
        }
    }

    /// Is the certificate valid at a time?
    ///
    /// - Parameter date: The time.
    /// - Returns: `true` from ``notBefore`` to ``notAfter``, both included.
    func isValid(at date: Date) -> Bool {
        notBefore <= date && date <= notAfter
    }

    /// Why the certificate isn't valid at a time.
    ///
    /// - Parameter date: The time, as this Mac's clock said it.
    /// - Returns: ``IndicatorPackError/notYetValid(certificate:from:clock:)`` before it's valid,
    ///   ``IndicatorPackError/expired(certificate:on:clock:)`` after, or `nil` while it's valid.
    func lapse(at date: Date) -> IndicatorPackError? {
        if date < notBefore { return .notYetValid(certificate: commonName, from: notBefore, clock: date) }
        if date > notAfter { return .expired(certificate: commonName, on: notAfter, clock: date) }
        return nil
    }

    /// The value of one entry `SecCertificateCopyValues` returned.
    ///
    /// - Parameter entry: The entry, a dictionary with `kSecPropertyKeyValue`.
    /// - Returns: Its value, or `nil`.
    private static func value(_ entry: Any?) -> Any? {
        (entry as? [String: Any])?[kSecPropertyKeyValue as String]
    }

    /// A validity date `SecCertificateCopyValues` returned.
    ///
    /// - Parameter entry: The entry, whose value is seconds since 2001.
    /// - Returns: The date, or `nil` when the entry has no number.
    private static func date(_ entry: Any?) -> Date? {
        (value(entry) as? NSNumber).map { Date(timeIntervalSinceReferenceDate: $0.doubleValue) }
    }
}
