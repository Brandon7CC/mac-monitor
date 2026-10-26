//
//  ProcessHelpers+CodeSigning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CryptoKit


// MARK: - Code signing
extension ProcessHelpers {
    /// The code signing certificates of the executable at a path, leaf first, read once per file
    /// (``CodeSigningCertificateCache``).
    ///
    /// - Parameter path: The executable's path.
    /// - Returns: Each certificate's subject summary and SHA-1 thumbprint, as new values. None if they can't be read.
    public static func getCodeSigningCerts(forBinaryAt path: String) -> [X509Cert] {
        CodeSigningCertificateCache.shared.certificates(at: path).map {
            X509Cert(summary: $0.summary, thumbprint: $0.thumbprint)
        }
    }
    
    /// Read the code signing certificates of the executable at a path from its signature, uncached.
    ///
    /// - Parameter path: The executable's path.
    /// - Returns: Each certificate's subject summary and SHA-1 thumbprint, leaf first: none if the signature has no
    ///   certificates (an adhoc signature), `nil` if it can't be read.
    static func readCodeSigningCerts(forBinaryAt path: String) -> [X509Cert]? {
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard let url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path as CFString, .cfurlposixPathStyle,
                                                      false),
              SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess, let information = information as? [String: Any] else {
            return nil
        }
        let chain = information[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        return chain.compactMap { certificate in
            guard let summary = SecCertificateCopySubjectSummary(certificate) as String? else { return nil }
            let thumbprint = Insecure.SHA1.hash(data: SecCertificateCopyData(certificate) as Data).withUnsafeBytes {
                ESLogger.hex(bytes: $0, uppercase: false)
            }
            return X509Cert(summary: summary, thumbprint: thumbprint)
        }
    }
    
    // MARK: - Code signing type
    /// The code signing type a validly signed executable's certificates tell (``CodeSigningCertificateCache``), for
    /// a process whose flags don't: not a platform binary, nor adhoc signed.
    ///
    /// - Parameter path: The executable's path.
    /// - Returns: ``CodeSigningType/appStore`` or ``CodeSigningType/developerId`` by the first certificate whose
    ///   subject names one, otherwise ``CodeSigningType/unknown``.
    static func certificateType(at path: String) -> CodeSigningType {
        for certificate in CodeSigningCertificateCache.shared.certificates(at: path) {
            if certificate.summary.hasPrefix("Apple Mac OS") { return .appStore }
            if certificate.summary.hasPrefix("Developer ID Application") { return .developerId }
        }
        return .unknown
    }
}


// MARK: - Code signing flags
/// One code signing flag: its bit and name in `<kern/cs_blobs.h>`, and what it means, from the header's comments.
public struct CodeSigningFlag: Identifiable, Hashable {
    public let bit: UInt32
    public let name: String
    public let summary: String
    public var id: UInt32 { bit }
}


extension ProcessHelpers {
    /// Each code signing flag, in bit order. Literal values: the header's constants are `Int32`, and
    /// `CS_DATAVAULT_CONTROLLER` (bit 31) has none.
    private static let codeSigningFlags: [CodeSigningFlag] = [
        (0x0000_0001, "CS_VALID", "Dynamically valid"),
        (0x0000_0002, "CS_ADHOC", "Adhoc signed"),
        (0x0000_0004, "CS_GET_TASK_ALLOW", "Has the get-task-allow entitlement"),
        (0x0000_0008, "CS_INSTALLER", "Has an installer entitlement"),
        (0x0000_0010, "CS_FORCED_LV", "Library validation required by the hardened system policy"),
        (0x0000_0020, "CS_INVALID_ALLOWED", "Page invalidation allowed by the task port policy"),
        (0x0000_0100, "CS_HARD", "Doesn't load invalid pages"),
        (0x0000_0200, "CS_KILL", "Killed if it becomes invalid"),
        (0x0000_0400, "CS_CHECK_EXPIRATION", "Certificate expiration checked"),
        (0x0000_0800, "CS_RESTRICT", "dyld treats it as restricted"),
        (0x0000_1000, "CS_ENFORCEMENT", "Code signing enforced"),
        (0x0000_2000, "CS_REQUIRE_LV", "Library validation required"),
        (0x0000_4000, "CS_ENTITLEMENTS_VALIDATED", "Its signature permits restricted entitlements"),
        (0x0000_8000, "CS_NVRAM_UNRESTRICTED", "Has the restricted NVRAM variables entitlement"),
        (0x0001_0000, "CS_RUNTIME", "Hardened runtime"),
        (0x0002_0000, "CS_LINKER_SIGNED", "Signed by the linker, as a freshly compiled binary is"),
        (0x0010_0000, "CS_EXEC_SET_HARD", "Sets CS_HARD on what it execs"),
        (0x0020_0000, "CS_EXEC_SET_KILL", "Sets CS_KILL on what it execs"),
        (0x0040_0000, "CS_EXEC_SET_ENFORCEMENT", "Sets CS_ENFORCEMENT on what it execs"),
        (0x0080_0000, "CS_EXEC_INHERIT_SIP", "Sets CS_INSTALLER on what it execs"),
        (0x0100_0000, "CS_KILLED", "Killed by the kernel for being invalid"),
        (0x0200_0000, "CS_NO_UNTRUSTED_HELPERS", "The kernel loaded only a platform dyld or Rosetta"),
        (0x0400_0000, "CS_PLATFORM_BINARY", "A platform binary"),
        (0x0800_0000, "CS_PLATFORM_PATH", "A platform binary by its path"),
        (0x1000_0000, "CS_DEBUGGED", "Debugged now or before, and allowed to run with invalid pages"),
        (0x2000_0000, "CS_SIGNED", "Has a signature, which may have gone invalid"),
        (0x4000_0000, "CS_DEV_CODE", "Development signed: can't load into production signed code"),
        (0x8000_0000, "CS_DATAVAULT_CONTROLLER", "Has the Data Vault controller entitlement"),
    ].map { CodeSigningFlag(bit: $0.0, name: $0.1, summary: $0.2) }

    /// The flags set in a process's code signing flags.
    ///
    /// - Parameter flags: `es_process_t`'s `codesigning_flags`, a `uint32_t`.
    /// - Returns: The flags, in bit order.
    public static func codeSigningFlags(_ flags: Int64) -> [CodeSigningFlag] {
        let bits = UInt32(truncatingIfNeeded: flags)
        return codeSigningFlags.filter { bits & $0.bit != 0 }
    }

    /// The names of the flags set in a process's code signing flags, such as `CS_VALID` and `CS_RUNTIME` (the
    /// hardened runtime). Adhoc with `CS_LINKER_SIGNED` is what the linker signs a freshly compiled binary with.
    ///
    /// - Parameter flags: `es_process_t`'s `codesigning_flags`, a `uint32_t`.
    /// - Returns: The names, in bit order.
    public static func codeSigningFlagNames(_ flags: Int64) -> [String] {
        codeSigningFlags(flags).map(\.name)
    }
}
