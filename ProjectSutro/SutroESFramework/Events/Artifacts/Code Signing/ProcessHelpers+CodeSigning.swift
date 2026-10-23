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
    ///   certificates (an ad hoc signature), `nil` if it can't be read.
    static func readCodeSigningCerts(forBinaryAt path: String) -> [X509Cert]? {
        var staticCode: SecStaticCode?
        guard let url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path as CFString, .cfurlposixPathStyle, false) else {
            return nil
        }
        
        let createFlags: SecCSFlags = []
        var status = SecStaticCodeCreateWithPath(url, createFlags, &staticCode)
        
        guard status == errSecSuccess, let staticCode = staticCode else {
            return nil
        }
        
        var dict: CFDictionary?
        let infoFlags: SecCSFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        status = SecCodeCopySigningInformation(staticCode, infoFlags, &dict)
        guard status == errSecSuccess, let infoDict = dict as? [String: Any] else {
            return nil
        }
        
        let certificateChainKey = kSecCodeInfoCertificates as String
        guard let certificateChain = infoDict[certificateChainKey] as? [SecCertificate] else {
            return []
        }
        
        var chain: [X509Cert] = []
        for certificate in certificateChain {
            if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
                let certificateData = SecCertificateCopyData(certificate) as Data
                let thumbprint = Insecure.SHA1.hash(data: certificateData).withUnsafeBytes {
                    ESLogger.hex(bytes: $0, uppercase: false)
                }
                chain.append(X509Cert(summary: summary, thumbprint: thumbprint))
            }
        }
        
        return chain
    }
    
    // MARK: - Code Signing Type
    public static func codeSigningType(for process: es_process_t) -> CodeSigningType {
        // Helper function to determine type from certificates
        func certType(forPath path: String) -> CodeSigningType? {
            let certificates = CodeSigningCertificateCache.shared.certificates(at: path)
            
            for cert in certificates {
                let summary = cert.summary
                if summary.hasPrefix("Apple Mac OS") {
                    return .appStore
                } else if summary.hasPrefix("Developer ID Application") {
                    return .developerId
                }
            }
            return nil
        }
        
        // Platform binary
        if process.is_platform_binary {
            return .platform
        }
        
        // Adhoc binary
        if (Int(process.codesigning_flags) & Int(CS_ADHOC)) == Int(CS_ADHOC) {
            return .adhoc
        }
        
        // Is validly signed. The flags are a `uint32_t`: read by bit pattern, since one with bit 31 set has no `Int32`.
        let csValid = (Int32(bitPattern: process.codesigning_flags) & CS_VALID) == CS_VALID
        if csValid, let executablePath = process.executable.pointee.path.string, !executablePath.isEmpty {
            
            // Check the codesinging certificates
            if let type = certType(forPath: executablePath) {
                return type
            }
            
            return .unknown
        }
        
        // Not validly signed
        return .unsigned
    }
}


// MARK: - Code signing flags
extension ProcessHelpers {
    /// Each code signing flag's bit and name, from `<kern/cs_blobs.h>`, in bit order. Literal values: the header's
    /// constants are `Int32`, and `CS_DATAVAULT_CONTROLLER` (bit 31) has none.
    private static let codeSigningFlags: [(bit: UInt32, name: String)] = [
        (0x0000_0001, "CS_VALID"), (0x0000_0002, "CS_ADHOC"), (0x0000_0004, "CS_GET_TASK_ALLOW"),
        (0x0000_0008, "CS_INSTALLER"), (0x0000_0010, "CS_FORCED_LV"), (0x0000_0020, "CS_INVALID_ALLOWED"),
        (0x0000_0100, "CS_HARD"), (0x0000_0200, "CS_KILL"), (0x0000_0400, "CS_CHECK_EXPIRATION"),
        (0x0000_0800, "CS_RESTRICT"), (0x0000_1000, "CS_ENFORCEMENT"), (0x0000_2000, "CS_REQUIRE_LV"),
        (0x0000_4000, "CS_ENTITLEMENTS_VALIDATED"), (0x0000_8000, "CS_NVRAM_UNRESTRICTED"),
        (0x0001_0000, "CS_RUNTIME"), (0x0002_0000, "CS_LINKER_SIGNED"), (0x0010_0000, "CS_EXEC_SET_HARD"),
        (0x0020_0000, "CS_EXEC_SET_KILL"), (0x0040_0000, "CS_EXEC_SET_ENFORCEMENT"),
        (0x0080_0000, "CS_EXEC_INHERIT_SIP"), (0x0100_0000, "CS_KILLED"), (0x0200_0000, "CS_NO_UNTRUSTED_HELPERS"),
        (0x0400_0000, "CS_PLATFORM_BINARY"), (0x0800_0000, "CS_PLATFORM_PATH"), (0x1000_0000, "CS_DEBUGGED"),
        (0x2000_0000, "CS_SIGNED"), (0x4000_0000, "CS_DEV_CODE"), (0x8000_0000, "CS_DATAVAULT_CONTROLLER"),
    ]

    /// The names of the flags set in a process's code signing flags, such as `CS_VALID` and `CS_RUNTIME` (the
    /// hardened runtime). Ad hoc with `CS_LINKER_SIGNED` is what the linker signs a freshly compiled binary with.
    ///
    /// - Parameter flags: `es_process_t`'s `codesigning_flags`, a `uint32_t`.
    /// - Returns: The names, in bit order.
    public static func codeSigningFlagNames(_ flags: Int64) -> [String] {
        let bits = UInt32(truncatingIfNeeded: flags)
        return codeSigningFlags.filter { bits & $0.bit != 0 }.map(\.name)
    }
}
