//
//  ESLoggerHexTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
import CryptoKit
@testable import SutroESFramework


// MARK: - Hex from a lookup table
/// Pins that ``ESLogger/hex(bytes:uppercase:)`` writes exactly what `String(format: "%02X")` (or `"%02hhx"`) per byte
/// wrote before it: hashes in uppercase, certificate thumbprints in lowercase.
final class ESLoggerHexTests: XCTestCase {
    /// Bytes in hex as Mac Monitor wrote them before the lookup table.
    ///
    /// - Parameters:
    ///   - bytes: The bytes.
    ///   - uppercase: `%02X` rather than `%02hhx`.
    /// - Returns: Two hex digits per byte.
    private func formatted(_ bytes: [UInt8], uppercase: Bool) -> String {
        bytes.map { String(format: uppercase ? "%02X" : "%02hhx", $0) }.joined()
    }
    
    /// Every byte value, in both cases.
    func testEveryByteMatchesStringFormat() {
        let bytes = (0...255).map(UInt8.init)
        for uppercase in [true, false] {
            let hex = bytes.withUnsafeBytes { ESLogger.hex(bytes: $0, uppercase: uppercase) }
            XCTAssertEqual(hex, formatted(bytes, uppercase: uppercase))
        }
    }
    
    /// Random buffers of every length up to a SHA-512, in both cases.
    func testRandomBytesMatchStringFormat() {
        var generator = SystemRandomNumberGenerator()
        for length in 0...64 {
            for _ in 0..<20 {
                let bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                for uppercase in [true, false] {
                    let hex = bytes.withUnsafeBytes { ESLogger.hex(bytes: $0, uppercase: uppercase) }
                    XCTAssertEqual(hex, formatted(bytes, uppercase: uppercase))
                }
            }
        }
    }
    
    /// No bytes are no digits.
    func testNoBytesIsEmpty() {
        XCTAssertEqual(ESLogger.hex(bytes: UnsafeRawBufferPointer(start: nil, count: 0)), "")
    }
    
    /// A value of type `T` with random bytes, such as an `es_cdhash_t` (a C array, imported as a tuple).
    ///
    /// - Parameter value: Any value of the type, overwritten.
    /// - Returns: The value with random bytes.
    private func randomized<T>(_ value: T) -> T {
        var value = value
        withUnsafeMutableBytes(of: &value) { bytes in
            for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max) }
        }
        return value
    }
    
    /// Fixed-size values (an `es_cdhash_t`, an `es_sha256_t`) are their bytes in uppercase, as `%02X` wrote them.
    func testFixedSizeValuesMatchStringFormat() {
        for _ in 0..<200 {
            let cdhash = randomized((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) as es_cdhash_t)
            let sha256 = randomized((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) as es_sha256_t)
            XCTAssertEqual(cdhashToString(cdhash: cdhash),
                           withUnsafeBytes(of: cdhash) { formatted(Array($0), uppercase: true) })
            XCTAssertEqual(sha256HexString(sha256),
                           withUnsafeBytes(of: sha256) { formatted(Array($0), uppercase: true) })
        }
    }
    
    /// The SHA-1 thumbprints of an executable's code signing certificates, as Mac Monitor wrote them before the lookup
    /// table (`String(format: "%02hhx")` per byte).
    ///
    /// - Parameter path: The executable's path.
    /// - Returns: The thumbprints, leaf first.
    /// - Throws: An `XCTest` failure if the signature can't be read.
    private func formattedThumbprints(of path: String) throws -> [String] {
        var code: SecStaticCode?
        XCTAssertEqual(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code), errSecSuccess)
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        XCTAssertEqual(SecCodeCopySigningInformation(try XCTUnwrap(code), flags, &information), errSecSuccess)
        let dictionary = try XCTUnwrap(information as? [String: Any])
        let certificates = try XCTUnwrap(dictionary[kSecCodeInfoCertificates as String] as? [SecCertificate])
        return certificates.map { certificate in
            let data = SecCertificateCopyData(certificate) as Data
            return Insecure.SHA1.hash(data: data).map { String(format: "%02hhx", $0) }.joined()
        }
    }
    
    /// A certificate's thumbprint is its SHA-1 in lowercase hex, as `%02hhx` wrote it.
    ///
    /// - Throws: An `XCTest` failure if the signature can't be read.
    func testCertificateThumbprintsMatchStringFormat() throws {
        let chain = ProcessHelpers.getCodeSigningCerts(forBinaryAt: "/usr/bin/true")
        XCTAssertFalse(chain.isEmpty)
        XCTAssertEqual(chain.map(\.thumbprint), try formattedThumbprints(of: "/usr/bin/true"))
    }
}
