//
//  LinkedIndicatorPack.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation
import MachO


// MARK: - The linked indicator pack
/// The signed indicator pack this build links in: the newest release of the indicators repository when the build was
/// made, exactly as it was signed (``IndicatorPackFile``). Its indicators are the ones Mac Monitor ships
/// (``Indicator/defaults``), and its sequence is the one a pack installed later must be above
/// (``IndicatorBaseline/linked``).
///
/// The linker copies `Indicators/LinkedIndicatorPack.json` into the framework's binary as its `__TEXT,__indicators`
/// section (the target's `OTHER_LDFLAGS`), so the code signature covers it and it isn't a file in the app to open
/// or replace. Its own signature isn't checked again as it's read. A test verifies the file as the Security
/// Extension verifies a pack before installing it.
///
/// `Scripts/Generate/link-indicator-pack.sh` copies a release's signed pack in.
enum LinkedIndicatorPack {
    /// Why the file can't be used.
    struct Problem: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    /// The segment the linker puts the file in.
    static let segment = "__TEXT"
    /// The file's section in it.
    static let section = "__indicators"

    /// The pack in this binary, read once. A binary without it, or with one that doesn't read, was built wrong.
    /// It stops here rather than run with no indicators of its own, which would drop every saved reference to one.
    static let pack: IndicatorPack = {
        guard let data = embedded() else { fatalError("The binary has no \(segment),\(section) section.") }
        do {
            return try decode(data)
        } catch {
            fatalError("The linked indicator pack can't be used: \(error)")
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

    /// Read a signed pack's file as the build's own. Its signature is left to whoever links it in.
    ///
    /// - Parameter data: The file's bytes.
    /// - Returns: The pack.
    /// - Throws: ``IndicatorPackError`` for a file that isn't a signed pack's, ``IndicatorPack/Problem`` for a
    ///   payload that isn't a pack, or a ``Problem`` for one that isn't a release, lists no indicators, or has one
    ///   this build can't run.
    static func decode(_ data: Data) throws -> IndicatorPack {
        let pack = try IndicatorPack.decode(try IndicatorPackFile(data).payload)
        guard pack.pack.sequence > 0 else { throw Problem(description: "It isn't a release: its sequence is 0.") }
        guard !pack.indicators.isEmpty else { throw Problem(description: "It lists no indicators.") }
        if let newer = pack.newer.first {
            throw Problem(description: "“\(newer.name)” needs Mac Monitor \(newer.minEngine), newer than this build.")
        }
        return pack
    }
}
