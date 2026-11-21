//
//  IndicatorPackFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reading a pack file
/// Pins the pack file's shape, which `tools/mmilib/pack.py` writes: at most 4 MiB, JSON, this format and version,
/// and a base64 payload and signature. A file that isn't one is refused before its signature is looked at, and the
/// verifier refuses it the same way.
final class IndicatorPackFileTests: XCTestCase {
    /// What reading a file, and verifying it, throw.
    ///
    /// - Parameter file: The file's bytes.
    /// - Returns: Reading's error, or `nil` when it reads, and whether verifying threw the same in both modes.
    private func refusal(_ file: Data) throws -> (error: IndicatorPackError?, verifierAgrees: Bool) {
        let error = thrown(IndicatorPackError.self) { try IndicatorPackFile(file) }
        let verifier = try packVerifier()
        let agrees = [.installing, .loading].allSatisfy { packRefusal(file, $0, by: verifier) == error }
        return (error, agrees)
    }

    /// The fixture reads as `pack.py` writes it: the payload's bytes and the signature's, decoded.
    func testThePackReadsAsPackPyWritesIt() throws {
        let file = try IndicatorPackFile(try fixture("indicator-pack.json"))
        XCTAssertEqual(file.payload, try fixture("indicator-pack-payload.json"))
        XCTAssertEqual(file.signature.first, 0x30, "a DER SEQUENCE")
        XCTAssertEqual(IndicatorPackFile.format, "com.swiftlydetecting.indicator-pack")
        XCTAssertEqual(IndicatorPackFile.currentVersion, 1)
    }

    /// Garbage is unreadable: no bytes, text, JSON that isn't an object, an object without a format or version or
    /// with them of the wrong type, no payload or an empty one, and a payload or signature that isn't base64.
    func testGarbageFails() throws {
        let garbage = ["", "garbage", "[]", "null", "{}", #"{"format": "com.swiftlydetecting.indicator-pack"}"#,
                       #"{"format": "com.swiftlydetecting.indicator-pack", "version": "1", "payload": "e30="}"#,
                       #"{"format": 1, "version": 1}"#].map { Data($0.utf8) }
        let changed = [
            try packFile { $0["payload"] = nil },
            try packFile { $0["payload"] = "" },
            try packFile { $0["payload"] = "not base64!" },
            try packFile { $0["payload"] = 7 },
            try packFile { $0["signature"] = "not base64!" },
        ]
        for file in garbage + changed {
            let (error, agrees) = try refusal(file)
            XCTAssertEqual(error, .unreadable, String(decoding: file, as: UTF8.self))
            XCTAssertTrue(agrees, String(decoding: file, as: UTF8.self))
        }
    }

    /// A file of exactly 4 MiB is read and verified, and one byte more is refused before it's parsed.
    func testAnOversizedFileFails() throws {
        var file = try fixture("indicator-pack.json")
        file.append(Data(repeating: 0x20, count: IndicatorLimits.maxFileBytes - file.count))
        XCTAssertEqual(file.count, 4 << 20)
        XCTAssertNoThrow(try packVerifier().verify(file, .installing))

        file.append(0x20)
        let (error, agrees) = try refusal(file)
        XCTAssertEqual(error, .tooLarge(bytes: IndicatorLimits.maxFileBytes + 1))
        XCTAssertTrue(agrees)
        XCTAssertEqual(error?.message, "The pack is 4194305 bytes, larger than 4 MiB.")
        XCTAssertEqual(try refusal(Data(repeating: 0x7b, count: IndicatorLimits.maxFileBytes + 1)).error,
                       .tooLarge(bytes: IndicatorLimits.maxFileBytes + 1))
    }

    /// Another format, such as the payload's own, is refused for its format whatever its version. A version other
    /// than 1 is refused as newer, or as one no Mac Monitor reads.
    func testAnUnknownFormatOrVersionFails() throws {
        let cases: [(file: Data, error: IndicatorPackError, message: String)] = [
            (try packFile { $0["format"] = "com.swiftlydetecting.indicators" },
             .unknownFormat("com.swiftlydetecting.indicators"),
             "The file is “com.swiftlydetecting.indicators”, not a signed indicator pack."),
            (try packFile { $0["format"] = "com.example.pack"; $0["version"] = 2 }, .unknownFormat("com.example.pack"),
             "The file is “com.example.pack”, not a signed indicator pack."),
            (try packFile { $0["version"] = 2 }, .unsupportedVersion(2),
             "The pack is version 2, from a newer Mac Monitor."),
            (try packFile { $0["version"] = 0 }, .unsupportedVersion(0),
             "The pack is version 0, which no Mac Monitor reads."),
            (try packFile { $0["version"] = 2; $0["payload"] = nil }, .unsupportedVersion(2),
             "The pack is version 2, from a newer Mac Monitor."),
        ]
        for (file, expected, message) in cases {
            let (error, agrees) = try refusal(file)
            XCTAssertEqual(error, expected)
            XCTAssertTrue(agrees, "\(expected)")
            XCTAssertEqual(error?.message, message)
        }
    }

    /// A pack without a signature, or with an empty one, is unsigned. A signature that's base64 but isn't CMS is
    /// unreadable to `CMSDecoder`.
    func testAnUnsignedPackFails() throws {
        for file in [try packFile { $0["signature"] = nil }, try packFile { $0["signature"] = "" }] {
            let (error, agrees) = try refusal(file)
            XCTAssertEqual(error, .unsigned)
            XCTAssertTrue(agrees)
        }
        let notCMS = try packFile { $0["signature"] = Data("garbage".utf8).base64EncodedString() }
        XCTAssertNil(try refusal(notCMS).error)
        for mode in [IndicatorPackVerifier.Mode.installing, .loading] {
            XCTAssertEqual(packRefusal(notCMS, mode, by: try packVerifier()), .unreadableSignature)
        }
        XCTAssertEqual(IndicatorPackError.unsigned.message, "The pack isn't signed.")
    }
}
