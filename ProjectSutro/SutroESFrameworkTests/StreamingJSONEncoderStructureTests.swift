//
//  StreamingJSONEncoderStructureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Values to encode
/// Every shape a synthesized conformance gives: scalars, optionals, nested values, arrays, a dictionary, an enum with
/// associated values, and a value with nothing to encode.
private struct Sample: Codable {
    /// An enum with associated values, as `EventType` is.
    enum Kind: Codable {
        case file(path: String, size: Int?)
        case pair(Int, String)
        case unknown
    }
    
    /// A value with no stored properties: `{}`.
    struct Nothing: Codable {}
    
    var name = "sample"
    var count = 3
    var ratio = 0.25
    var flag = true
    var missing: String?
    var present: String? = "here"
    var nested = [Kind.file(path: "/tmp/a", size: nil), .pair(1, "b"), .unknown]
    var empty: [Int] = []
    var nothing = Nothing()
    var table = ["b": 2, "a": 1]
    var grid = [[1, 2], [], [3]]
    var stamp = Date(timeIntervalSince1970: 1_791_072_114)
    var identifier = UUID()
}

/// Goes back to a nested object after encoding a later member, which can't be streamed.
private struct Interleaved: Encodable {
    /// The keys.
    enum Keys: String, CodingKey { case first, second, third }
    
    /// Open the first member's object, write the second member, then write to the first member's object again.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: The encoder's error.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        var first = container.nestedContainer(keyedBy: Keys.self, forKey: .first)
        try first.encode(1, forKey: .first)
        try container.encode("two", forKey: .second)
        try first.encode(3, forKey: .third)
    }
}

/// Encodes through `superEncoder()`, which isn't streamed.
private struct WithSuper: Encodable {
    /// The keys.
    enum Keys: String, CodingKey { case own }
    
    /// Write a member, then a value through each `superEncoder`.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: The encoder's error.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode("mine", forKey: .own)
        try Sample.Nothing().encode(to: container.superEncoder())
        var array = container.superEncoder(forKey: .own).unkeyedContainer()
        try array.encode(7)
    }
}

/// Asks for its keyed container twice, which `JSONEncoder` allows: both write to one object.
private struct TwoContainers: Encodable {
    /// The keys.
    enum Keys: String, CodingKey { case a, b }
    
    /// Write one member through each of two keyed containers.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: The encoder's error.
    func encode(to encoder: Encoder) throws {
        var first = encoder.container(keyedBy: Keys.self)
        try first.encode(1, forKey: .a)
        var second = encoder.container(keyedBy: Keys.self)
        try second.encode(2, forKey: .b)
    }
}

/// Encodes nothing at all.
private struct Silent: Encodable {
    /// Write nothing.
    ///
    /// - Parameter encoder: The encoder, unused.
    /// - Throws: Never.
    func encode(to encoder: Encoder) throws {}
}


// MARK: - Structures
/// Pins ``StreamingJSONEncoder``'s objects and arrays to `JSONEncoder`'s, byte for byte once members are sorted, and
/// its fallback to `JSONEncoder` for what it can't stream.
final class StreamingJSONEncoderStructureTests: XCTestCase {
    /// Encode with both encoders and require the same bytes, in canonical form.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - encoder: The streaming encoder to use.
    ///   - line: The caller's line, for failures.
    /// - Throws: Either encoder's error.
    private func assertSameJSON<T: Encodable>(_ value: T, encoder: StreamingJSONEncoder = StreamingJSONEncoder(),
                                              line: UInt = #line) throws {
        let expected = try JSONCanonicalForm.canonical(try JSONEncoder().encode(value))
        XCTAssertEqual(try JSONCanonicalForm.canonical(try encoder.encode(value)), expected, line: line)
    }
    
    /// Objects, optionals left out or written, nested values, empty arrays and objects, a dictionary, an enum with
    /// associated values and one without, and arrays of arrays.
    ///
    /// - Throws: Either encoder's error.
    func testSynthesizedConformancesMatch() throws {
        try assertSameJSON(Sample())
        try assertSameJSON([Sample(), Sample(missing: "now set", present: nil, nested: [], table: [:])])
        try assertSameJSON(Sample.Kind.unknown)
        try assertSameJSON(Sample.Nothing())
        try assertSameJSON([Sample.Nothing()])
    }
    
    /// Members come out in the order `encode(to:)` encodes them: a synthesized conformance's declaration order.
    ///
    /// - Throws: The encoder's error.
    func testMembersKeepTheirEncodingOrder() throws {
        let json = String(decoding: try StreamingJSONEncoder().encode(TwoContainers()), as: UTF8.self)
        XCTAssertEqual(json, #"{"a":1,"b":2}"#)
    }
    
    /// What can't be streamed is encoded by `JSONEncoder`: a container used again after a later one, and
    /// `superEncoder()`.
    ///
    /// - Throws: Either encoder's error.
    func testUnstreamableValuesFallBackToJSONEncoder() throws {
        try assertSameJSON(Interleaved())
        try assertSameJSON(WithSuper())
        try assertSameJSON(["a": [Interleaved()]])
        let encoder = StreamingJSONEncoder()
        try assertSameJSON(Interleaved(), encoder: encoder)
        try assertSameJSON(Sample(), encoder: encoder)
    }
    
    /// A value that encodes nothing is refused at the top, as `JSONEncoder` refuses it, and is `{}` inside another.
    ///
    /// - Throws: Either encoder's error.
    func testSilentValues() throws {
        XCTAssertThrowsError(try JSONEncoder().encode(Silent()))
        XCTAssertThrowsError(try StreamingJSONEncoder().encode(Silent()))
        try assertSameJSON([Silent(), Silent()])
        XCTAssertEqual(String(decoding: try StreamingJSONEncoder().encode([Silent()]), as: UTF8.self), "[{}]")
    }
    
    /// One encoder encodes value after value, including one far larger than its buffer, each as a new encoder would.
    ///
    /// - Throws: Either encoder's error.
    func testEncoderIsReusable() throws {
        let encoder = StreamingJSONEncoder()
        let large = Sample(name: String(repeating: "x/\"", count: 1_000_000))
        for value in [Sample(), large, Sample(name: "after"), Sample()] {
            XCTAssertEqual(try encoder.encode(value), try StreamingJSONEncoder().encode(value))
            try assertSameJSON(value, encoder: encoder)
        }
        XCTAssertLessThanOrEqual(encoder.state.pointee.capacity, StreamingJSONEncoder.retainedCapacityLimit)
    }
}
