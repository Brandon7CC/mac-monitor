//
//  NStatFixture.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Recorded network statistics messages
/// One message from `Fixtures/nstat-darwin22.txt` or `nstat-darwin27.txt`: the kernel's messages and the client's
/// requests on the macOS 13.6 and 27.2 test VMs, at most three of each kind, with the values the reference decoder
/// read from each (`nstat-darwin*-decoded.txt`, line for line). The kinds were kept apart, so source references
/// jump and some updates have no add: they're for reading one message at a time, never for replaying as a stream.
struct NStatFixtureMessage {
    /// `in` from the kernel, or `out` from the client.
    let direction: String
    let run: String
    let bytes: [UInt8]
    /// The decoded values by name, such as `pname`, `local` or `upid`. Lists of items are left out.
    let decoded: [String: String]

    /// - Parameter key: A decoded value's name.
    /// - Returns: The value as an integer, or `nil` when it's absent or isn't one.
    func number(_ key: String) -> UInt64? {
        decoded[key].flatMap { UInt64($0) }
    }
}


extension XCTestCase {
    /// The recorded messages of one Darwin version.
    ///
    /// - Parameter darwin: 22 or 27.
    /// - Returns: The messages, in the order they were recorded.
    /// - Throws: An `XCTest` failure when a fixture is missing, or its two files don't line up.
    func nstatMessages(darwin: Int) throws -> [NStatFixtureMessage] {
        let raw = try lines(of: "nstat-darwin\(darwin).txt").filter { $0.contains("hex=") }
        let decoded = try lines(of: "nstat-darwin\(darwin)-decoded.txt")
        XCTAssertEqual(raw.count, decoded.count, "The decoded file has a line for each message")
        return zip(raw, decoded).map { line, values in
            let fields = Self.fields(line), decodedFields = Self.fields(values.components(separatedBy: " items=")[0])
            let hex = Array(fields["hex", default: ""].utf8)
            let bytes = stride(from: 0, to: hex.count - 1, by: 2).compactMap {
                UInt8(String(decoding: hex[$0...$0 + 1], as: UTF8.self), radix: 16)
            }
            return NStatFixtureMessage(direction: fields["dir", default: ""], run: fields["run", default: ""],
                                       bytes: bytes, decoded: decodedFields)
        }
    }

    /// The recorded messages that carry a descriptor of a provider the client reads, with where it starts.
    ///
    /// - Parameter darwin: 22 or 27.
    /// - Returns: Each message, its provider and its descriptor's offset.
    /// - Throws: An `XCTest` failure when the fixture is missing.
    func descriptorMessages(darwin: Int) throws
        -> [(message: NStatFixtureMessage, provider: NStat.Provider, offset: Int)] {
        try nstatMessages(darwin: darwin).compactMap { message in
            guard let type = message.number("type"), [10_003, 10_006, 10_007].contains(type),
                  let provider = message.number("provider").flatMap({ NStat.Provider(rawValue: UInt32($0)) }) else {
                return nil
            }
            return (message, provider, type == 10_003 ? 40 : 152)
        }
    }

    /// The non-empty lines of a fixture.
    ///
    /// - Parameter name: The fixture's name.
    /// - Returns: The lines.
    /// - Throws: An `XCTest` failure when it's missing.
    private func lines(of name: String) throws -> [String] {
        String(decoding: try fixture(name), as: UTF8.self).split(separator: "\n").map(String.init)
    }

    /// The `name=value` fields of a line.
    ///
    /// - Parameter line: The line.
    /// - Returns: The values by name.
    private static func fields(_ line: String) -> [String: String] {
        Dictionary(line.split(separator: " ").compactMap { field in
            field.firstIndex(of: "=").map { (String(field[..<$0]), String(field[field.index(after: $0)...])) }
        }) { first, _ in first }
    }
}
