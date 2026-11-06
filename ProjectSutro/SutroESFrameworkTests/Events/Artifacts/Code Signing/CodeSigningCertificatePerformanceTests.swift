//
//  CodeSigningCertificatePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Code signing certificates
/// Times reading an executable's code signing certificates, which every exec of a validly signed image does and every
/// event of a third-party process's needs for its code signing type: uncached (`SecCodeCopySigningInformation`,
/// with trust evaluated by `trustd`), and a hit in ``CodeSigningCertificateCache``, a `stat(2)` and a table lookup.
///
/// `/usr/bin/true` is on every Mac, signed by Apple with a three certificate chain.
final class CodeSigningCertificatePerformanceTests: PerformanceTestCase {
    /// The executable read.
    private static let executable = "/usr/bin/true"
    
    /// The certificates read from the signature each time.
    func testUncachedRead() throws {
        let reads = 50
        try benchmark("enrich.certificates.uncached", unit: "file", operations: reads) {
            for _ in 0..<reads {
                guard let certificates = ProcessHelpers.readCodeSigningCerts(forBinaryAt: Self.executable),
                      !certificates.isEmpty else { throw BenchmarkFailure("No certificates in \(Self.executable)") }
            }
        }
    }
    
    /// The certificates from the cache, once they've been read.
    func testCacheHit() throws {
        let cache = CodeSigningCertificateCache()
        let lookups = 20_000
        try benchmark("enrich.certificates.cached", unit: "lookup", operations: lookups) {
            for _ in 0..<lookups where cache.certificates(at: Self.executable).isEmpty {
                throw BenchmarkFailure("No certificates for \(Self.executable)")
            }
        }
    }
}
