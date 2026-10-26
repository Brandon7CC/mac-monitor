//
//  StreamingJSONEncoderArtifactTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Artifacts
/// Pins the artifacts ``StreamingJSONEncoder`` writes member by member (``StreamingJSONEncoder/writeArtifact(_:)``) to
/// what their synthesized `encode(to:)` writes: every stored property, in declaration order, so one added to a type but
/// not to its writer fails here; and, with keys sorted, every message is byte for byte `JSONEncoder`'s.
final class StreamingJSONEncoderArtifactTests: XCTestCase {
    /// An object's own keys, in the order they're written.
    ///
    /// - Parameter json: An object's JSON.
    /// - Returns: Its members' keys, without those of the objects inside it.
    private func keys(_ json: Data) -> [String] {
        var keys: [String] = [], depth = 0, inString = false, escaped = false, text: [UInt8] = [], last = ""
        for byte in json {
            if inString {
                if escaped {
                    escaped = false
                    text.append(byte)
                } else if byte == UInt8(ascii: "\\") {
                    escaped = true
                } else if byte == UInt8(ascii: "\"") {
                    inString = false
                    last = String(decoding: text, as: UTF8.self)
                } else {
                    text.append(byte)
                }
                continue
            }
            switch byte {
            case UInt8(ascii: "\""): (inString, text) = (true, [])
            case UInt8(ascii: "{"), UInt8(ascii: "["): depth += 1
            case UInt8(ascii: "}"), UInt8(ascii: "]"): depth -= 1
            case UInt8(ascii: ":") where depth == 1: keys.append(last)
            default: break
            }
        }
        return keys
    }

    /// Each artifact writes every stored property, in declaration order, with the values `JSONEncoder` writes.
    func testArtifactsWriteEveryStoredProperty() throws {
        let decoder = SyntheticDecoder(SyntheticVariant(name: "full", full: true))
        let artifacts: [(String, any Encodable)] = [
            ("File", try decoder.make(File.self)), ("Stat", try decoder.make(Stat.self)),
            ("TimeSpec", try decoder.make(TimeSpec.self)), ("TimeVal", try decoder.make(TimeVal.self)),
            ("AuditToken", try decoder.make(AuditToken.self)),
        ]
        /// Written member by member, not through `encode(to:)`.
        func isDirect<Artifact: Encodable>(_ artifact: Artifact) -> Bool {
            StreamingJSONEncoder().writeArtifact(artifact)
        }
        for (name, artifact) in artifacts {
            XCTAssertTrue(isDirect(artifact), "\(name) went through Codable")
            let json = try StreamingJSONEncoder().encode(artifact)
            XCTAssertEqual(keys(json), Mirror(reflecting: artifact).children.compactMap(\.label), name)
            XCTAssertEqual(try JSONCanonicalForm.canonical(json),
                           try JSONCanonicalForm.canonical(try JSONEncoder().encode(artifact)), name)
        }
    }

    /// With keys sorted and slashes left alone, every event type's synthetic messages and every fixture's events,
    /// artifacts and all, are byte for byte what `JSONEncoder` writes with those options.
    func testSortedMessagesMatchJSONEncoder() throws {
        try XCTSkipUnless(StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes,
                          "JSONEncoder here sorts as NSString compares")
        let streaming = StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false)
        let reference = JSONEncoder()
        reference.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let messages = try SyntheticCorpus.records().map { ($0.label, $0.message) }
            + allFixtureMessages().enumerated().map { ("fixture[\($0)]", $1) }
        var different: [String] = []
        for (label, message) in messages where try streaming.encode(message) != reference.encode(message) {
            different.append(label)
        }
        XCTAssertGreaterThan(messages.count, TelemetrySchemaSource.events.count * 2)
        XCTAssertEqual(different, [])
    }
}
