//
//  StaticCodeSigning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import Security


// MARK: - Static code signing
/// What a bundle's or a file's signature says, read statically from disk: `SecStaticCodeCreateWithPath` and
/// `SecCodeCopySigningInformation` with `kSecCSSigningInformation`, without validating the code.
///
/// For a process, Endpoint Security gives the kernel's view of its signature (``Process/codesigning_type``). A launch
/// item's bundle has no process yet, so its signature is read from the bundle itself. Reading one is a few
/// milliseconds (the certificates' trust is evaluated), which is fine for the rare events that ask for it, so nothing
/// is cached.
struct StaticCodeSigning: Equatable {
    /// The signing identifier, or `nil` for unsigned code.
    let signingID: String?
    /// The team identifier, or `nil` for Apple platform, adhoc and unsigned code.
    let teamID: String?
    /// How the code is signed.
    let type: CodeSigningType

    /// Where signatures are read (``read(path:)``), each waited for up to half a second: a few milliseconds is usual.
    private static let deadline = DeadlineQueue(label: "com.swiftlydetecting.sutro.static-code-signing",
                                                timeout: .milliseconds(500))

    /// Read the signature of the code at a path off the caller's thread, waiting only so long (``DeadlineQueue``).
    ///
    /// Security opens the files a signature is read from with a blocking `open(2)`, so a file swapped for a FIFO after
    /// it was checked (``LaunchItemBundle/isSafeToReadSignature(at:)``) would hang the read: the capture lane that
    /// asked doesn't hang with it.
    ///
    /// - Parameter path: A bundle directory or an executable.
    /// - Returns: The signing (``init(path:)``), or `nil` when the path isn't code Security can read, the read missed
    ///   its deadline, or an earlier read that did is still running.
    static func read(path: String) -> StaticCodeSigning? {
        deadline.run { StaticCodeSigning(path: path) }
    }

    /// Read the signature of the code at a path, on the caller's thread.
    ///
    /// - Parameter path: A bundle directory or an executable.
    /// - Returns: The signing, or `nil` when the path isn't code Security can read (it's missing, or neither a bundle
    ///   nor a Mach-O, script or other signable file).
    init?(path: String) {
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard let url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path as CFString, .cfurlposixPathStyle,
                                                      false),
              SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        let status = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation),
                                                   &information)
        guard status == errSecSuccess || status == errSecCSUnsigned else { return nil }
        self.init(information: information as? [String: Any] ?? [:])
    }

    /// The signing a signing information dictionary describes.
    ///
    /// - Parameter information: `SecCodeCopySigningInformation`'s dictionary.
    init(information: [String: Any]) {
        signingID = information[kSecCodeInfoIdentifier as String] as? String
        teamID = information[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (information[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let certificates = information[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        if signingID == nil {
            type = .unsigned
        } else if information[kSecCodeInfoPlatformIdentifier as String] != nil {
            type = .platform
        } else if flags & SecCodeSignatureFlags.adhoc.rawValue != 0 || certificates.isEmpty {
            type = .adhoc
        } else {
            type = ProcessHelpers.certificateType(
                summaries: certificates.compactMap { SecCertificateCopySubjectSummary($0) as String? })
        }
    }
}
