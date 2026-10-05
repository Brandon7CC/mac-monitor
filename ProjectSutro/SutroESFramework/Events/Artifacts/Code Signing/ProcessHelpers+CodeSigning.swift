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
    /// - Returns: Each certificate's subject summary and SHA-1 thumbprint, as new values; none if they can't be read.
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
