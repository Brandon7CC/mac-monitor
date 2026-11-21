//
//  IndicatorPack.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Indicator packs
/// An indicator pack's payload, as the indicators repository builds it (`tools/mmi build`) and a release signs it: the
/// indicator file (``IndicatorExchange``) at version 2, with the pack's header.
///
/// ```json
/// { "format": "com.swiftlydetecting.indicators", "version": 2,
///   "pack": { "sequence": 1, "published": "2026-11-15T09:35:16Z", "commit": "f8911d2...", "min_engine": "3.2.0",
///             "core": ["6D4D0F1D-..."], "retired": ["6D4D0F1D-..."] },
///   "indicators": [ { "id": "...", "revision": 2, "minEngine": "3.2.0", "name": "Login", ... } ] }
/// ```
///
/// An entry a newer Mac Monitor wrote, such as a kind of rule this build doesn't know, is kept as ``newer`` when its
/// `minEngine` says it needs that newer Mac Monitor. Any other entry that doesn't read fails the whole pack.
public struct IndicatorPack: Decodable, Equatable {
    /// What the pack says about itself.
    public struct Header: Decodable, Equatable {
        /// Which release it is: it goes up by one with every release, and 0 is a build that isn't one.
        public let sequence: Int
        /// When its commit was made, such as `2026-11-15T09:35:16Z`.
        public let published: String
        /// The indicators repository's commit it was built from.
        public let commit: String
        /// The oldest Mac Monitor that reads it.
        public let minEngine: ReleaseVersion
        /// The identities Mac Monitor's code depends on, each of which the pack has to have.
        public let core: [UUID]
        /// The identities never used again, which no pack has.
        public let retired: [UUID]

        private enum CodingKeys: String, CodingKey {
            case sequence, published, commit, core, retired
            case minEngine = "min_engine"
        }
    }

    /// An entry this build can't read, which needs a newer Mac Monitor.
    public struct Newer: Decodable, Equatable {
        public let id: UUID
        public let name: String
        /// The oldest Mac Monitor that can read it.
        public let minEngine: ReleaseVersion
    }

    /// Why a payload isn't a pack this build can use.
    public struct Problem: Error, Equatable, CustomStringConvertible {
        public let description: String
    }

    /// What the payload says it is: ``IndicatorExchange/format``.
    public let format: String
    /// The indicator file's version: 2 to ``IndicatorExchange/version``.
    public let version: Int
    /// The pack's header.
    public let pack: Header
    /// The indicators this build reads, in the pack's order. One whose `minEngine` is newer than this build is here,
    /// but isn't run (``Indicator/isSupported``).
    public let indicators: [Indicator]
    /// The entries a newer Mac Monitor wrote that this build can't read, in the pack's order.
    public let newer: [Newer]

    private enum CodingKeys: String, CodingKey {
        case format, version, pack, indicators
    }

    /// Decode a payload, each entry on its own.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When a key is missing or isn't what it should be, or an entry doesn't read and doesn't need a newer
    ///   Mac Monitor.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decode(String.self, forKey: .format)
        version = try container.decode(Int.self, forKey: .version)
        pack = try container.decode(Header.self, forKey: .pack)
        let entries = try container.decode([Entry].self, forKey: .indicators)
        indicators = entries.compactMap { if case .read(let indicator) = $0 { indicator } else { nil } }
        newer = entries.compactMap { if case .newer(let entry) = $0 { entry } else { nil } }
    }

    /// Read a pack's payload and check it: the indicator file at a version from 2 to the newest this build reads, a
    /// header whose `min_engine` this build meets, and indicators with no identity twice, every core identity among
    /// them and no retired one.
    ///
    /// - Parameter data: The payload's bytes.
    /// - Returns: The pack.
    /// - Throws: ``Problem`` saying what's wrong.
    public static func decode(_ data: Data) throws(Problem) -> IndicatorPack {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Problem(description: "It isn't a JSON object.")
        }
        guard object["format"] as? String == IndicatorExchange.format else {
            throw Problem(description: "It isn't Mac Monitor indicators.")
        }
        guard let fileVersion = object["version"] as? Int, fileVersion >= 2 else {
            throw Problem(description: "It's an indicator file, not a pack: it has no pack header.")
        }
        guard fileVersion <= IndicatorExchange.version else {
            throw Problem(description: "It's version \(fileVersion), newer than this Mac Monitor reads.")
        }
        let pack: IndicatorPack
        do {
            pack = try JSONDecoder().decode(IndicatorPack.self, from: data)
        } catch {
            throw Problem(description: "It can't be read: \(Self.reason(for: error))")
        }
        try pack.check()
        return pack
    }

    /// Check what decoding can't: the Mac Monitor it needs, and its identities.
    ///
    /// - Throws: ``Problem`` for the first that's wrong.
    private func check() throws(Problem) {
        guard pack.minEngine <= Indicator.engineVersion else {
            throw Problem(description: "It needs Mac Monitor \(pack.minEngine) or later.")
        }
        let ids = indicators.map(\.id) + newer.map(\.id)
        guard !ids.isEmpty else { throw Problem(description: "It has no indicators.") }
        var seen = Set<UUID>()
        for id in ids where !seen.insert(id).inserted {
            throw Problem(description: "Two of its indicators share the identity \(id.uuidString).")
        }
        if let missing = pack.core.first(where: { !seen.contains($0) }) {
            throw Problem(description: "It doesn't have the core indicator \(missing.uuidString).")
        }
        if let retired = pack.retired.first(where: seen.contains) {
            throw Problem(description: "It has the retired indicator \(retired.uuidString).")
        }
    }

    /// - Parameter error: A decoding error.
    /// - Returns: What's wrong, and where, in a sentence.
    private static func reason(for error: Error) -> String {
        guard let decoding = error as? DecodingError else { return "\(error)" }
        let context: DecodingError.Context
        switch decoding {
        case .keyNotFound(let key, let found): return "\(path(found.codingPath + [key])) is missing."
        case .typeMismatch(_, let found), .valueNotFound(_, let found), .dataCorrupted(let found): context = found
        @unknown default: return "\(error)"
        }
        return "\(path(context.codingPath)): \(context.debugDescription)"
    }

    /// - Parameter keys: A coding path.
    /// - Returns: It as a key path, such as `indicators[3].sequence.steps`.
    private static func path(_ keys: [CodingKey]) -> String {
        keys.reduce(into: "") { path, key in
            if let index = key.intValue {
                path += "[\(index)]"
            } else {
                path += path.isEmpty ? key.stringValue : ".\(key.stringValue)"
            }
        }
    }

    /// One of the pack's entries: an indicator this build reads, or one a newer Mac Monitor wrote.
    private enum Entry: Decodable {
        case read(Indicator)
        case newer(Newer)

        /// - Parameter decoder: The decoder.
        /// - Throws: The indicator's error, for an entry that doesn't read and doesn't need a newer Mac Monitor.
        init(from decoder: Decoder) throws {
            do {
                self = .read(try Indicator(from: decoder))
            } catch {
                guard let entry = try? Newer(from: decoder), entry.minEngine > Indicator.engineVersion else {
                    throw error
                }
                self = .newer(entry)
            }
        }
    }
}
