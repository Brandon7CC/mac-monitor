//
//  DefaultIndicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation
import MachO


// MARK: - The default indicators' file
/// The indicators Mac Monitor ships, as `Detection/DefaultIndicators.json` lists them, in the format an export writes
/// (``IndicatorExchange``). The linker copies the file into the
/// framework's binary as its `__TEXT,__indicators` section (the target's `OTHER_LDFLAGS`), so the code signature
/// covers it and it isn't a file in the app to open or replace.
///
/// The file is generated: `Scripts/generate-default-indicators.sh` writes it from the test target's source
/// (`SutroESFrameworkTests/Default Indicators/Source`), where each predicate is built from named parts, and a test
/// fails when the two differ.
enum DefaultIndicators {
    /// The file's top level.
    struct File: Decodable, Equatable {
        /// What the file says it is: ``IndicatorExchange/format``.
        let format: String
        /// The file's version: ``IndicatorExchange/version`` at most.
        let version: Int
        /// The indicators this build ships, in order.
        let indicators: [Indicator]
    }

    /// Why the file can't be used.
    struct Problem: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    /// The segment the linker puts the file in.
    static let segment = "__TEXT"
    /// The file's section in it.
    static let section = "__indicators"

    /// The file in this binary, decoded once. A binary without it, or with one that doesn't decode, was built wrong.
    /// It stops here rather than run with no defaults, which would drop every saved reference to one.
    static let file: File = {
        guard let data = embedded() else { fatalError("The binary has no \(segment),\(section) section.") }
        do {
            return try decode(data)
        } catch {
            fatalError("The default indicators can't be used: \(error)")
        }
    }()

    /// - Returns: The file's bytes, as the linker copied them into the binary this code is in, or `nil` when it has
    ///   none.
    static func embedded() -> Data? {
        var size: UInt = 0
        let header = #dsohandle.assumingMemoryBound(to: mach_header_64.self)
        guard let bytes = getsectiondata(header, segment, section, &size), size > 0 else { return nil }
        return Data(bytes: bytes, count: Int(size))
    }

    /// - Parameter data: The file's bytes.
    /// - Returns: The file.
    /// - Throws: The decoder's error, or a ``Problem`` when it's another format, a newer version, lists no
    ///   indicators or lists an identity twice.
    static func decode(_ data: Data) throws -> File {
        let file = try JSONDecoder().decode(File.self, from: data)
        guard file.format == IndicatorExchange.format else { throw Problem(description: "It's a \(file.format) file.") }
        guard file.version <= IndicatorExchange.version else {
            throw Problem(description: "It's version \(file.version), newer than this build reads.")
        }
        guard !file.indicators.isEmpty else { throw Problem(description: "It lists no indicators.") }
        guard Set(file.indicators.map(\.id)).count == file.indicators.count else {
            throw Problem(description: "Two of its indicators share an identity.")
        }
        return file
    }
}
