//
//  IndicatorPackUpdates.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation
import CryptoKit


// MARK: - Update mode
/// What the Security Extension does about newer indicator packs. Settings and `macmonitor indicators pack mode` set
/// it for the Mac.
public enum IndicatorPackMode: String, Codable, CaseIterable, Sendable {
    /// Never look for one on its own. A pack is still checked for, or installed, when someone who may change the
    /// indicators asks.
    case off
    /// Look for one once a day, and say when there is one. The default.
    case notify
    /// Look for one once a day, and install it.
    case automatic = "auto"
}


// MARK: - Update state
/// What the Security Extension remembers about looking for indicator packs (Security Extension context): the mode,
/// when it last looked, and what that found. It's kept as `indicator-updates.json` beside the saved set, root only.
///
/// ```json
/// { "version": 1, "mode": "notify", "checked": "2026-11-16T21:00:00Z", "looked": "2026-11-16T09:00:00Z",
///   "available": 3 }
/// ```
public struct IndicatorPackUpdates: Equatable {
    /// Does this build look for newer packs? Not in 3.2: the work is done and tested, and waits for a later release
    /// (`SavedIndicatorSet+Updates.swift`). While it's `false`, `macmonitor` has no `pack check` or `pack mode`,
    /// `pack install` needs a file, and nothing says an update mode, a last look or a newer pack. The tests of those
    /// turn it on.
    public static var isAvailable = false
    /// The version this build writes and reads.
    public static let currentVersion = 1
    /// How long after a look the Security Extension looks again on its own: a day.
    public static let checkInterval: TimeInterval = 24 * 60 * 60
    /// How long a look's answer stands in for another, whoever asks: five minutes.
    public static let answerLifetime: TimeInterval = 5 * 60
    /// How many times a pack may be being checked when the Security Extension stops before it's passed over.
    public static let strikes = 2
    /// The marker kept while packs are verified and checked (``SavedIndicatorSet``): a JSON array of the SHA-256 of
    /// each. One found at startup means the Security Extension stopped while it had them.
    public static let checkingLayout = RootFileStore.Layout(fileName: "indicator-pack.checking",
                                                            unreadableFileName: "indicator-pack.checking.unreadable",
                                                            temporaryPrefix: ".indicator-pack.checking.",
                                                            maxBytes: 16 * 1024,
                                                            noun: "indicator pack checking marker")
    /// The file, where an unreadable one is kept, and temporary files' prefix.
    public static let layout = RootFileStore.Layout(fileName: "indicator-updates.json",
                                                    unreadableFileName: "indicator-updates.unreadable.json",
                                                    temporaryPrefix: ".indicator-updates.", maxBytes: 64 * 1024,
                                                    noun: "indicator pack update state")

    /// What to do about newer packs.
    public var mode: IndicatorPackMode = .notify
    /// When GitHub was last asked, whoever asked.
    public var checked: Date?
    /// When the Security Extension last looked on its own and GitHub answered: what the next daily look is counted
    /// from. A look someone asks for doesn't move it, so nobody can put the daily look off by asking.
    public var looked: Date?
    /// The sequence of a newer pack the last look found and verified, which isn't installed. `nil` for none.
    public var available: Int?
    /// Why the last look found nothing it could use, as the user reads it. `nil` when it went well.
    public var problem: String?
    /// How many times the Security Extension stopped while it was checking a pack, by the pack file's SHA-256. One
    /// that reaches ``strikes`` is passed over (``isPassedOver(_:)``).
    public var stopped: [String: Int] = [:]

    /// The state of a Mac that never looked: the default mode.
    public init() {}

    /// Should the Security Extension look on its own now? Never while the mode is off, and otherwise once
    /// ``checkInterval`` has passed since its last look that GitHub answered (``looked``), when it never had one, or
    /// when the clock went back past it.
    ///
    /// - Parameter now: The time.
    /// - Returns: `true` when it should.
    public func isDue(at now: Date) -> Bool {
        guard mode != .off else { return false }
        return looked.map { now.timeIntervalSince($0) >= Self.checkInterval || now < $0 } ?? true
    }

    /// A pack file's SHA-256, in lowercase hex: how ``stopped`` names a pack without reading it.
    ///
    /// - Parameter file: The pack's file.
    /// - Returns: The digest.
    public static func digest(of file: Data) -> String {
        SHA256.hash(data: file).map { String(format: "%02x", $0) }.joined()
    }

    /// Count that the Security Extension stopped while it had these packs. Packs that stopped it only once are
    /// forgotten when there are many, so the list stays short.
    ///
    /// - Parameter digests: Each pack file's SHA-256.
    public mutating func strike(_ digests: some Sequence<String>) {
        for digest in Set(digests) { stopped[digest, default: 0] += 1 }
        if stopped.count > 32 { stopped = stopped.filter { $0.value >= Self.strikes } }
    }

    /// Is a pack passed over, because the Security Extension stopped ``strikes`` times while checking it?
    ///
    /// - Parameter digest: The pack file's SHA-256.
    /// - Returns: `true` when it is.
    public func isPassedOver(_ digest: String) -> Bool {
        (stopped[digest] ?? 0) >= Self.strikes
    }

    /// The file's bytes.
    ///
    /// - Returns: The JSON. Why the last look failed isn't kept: it's told until the Security Extension restarts.
    public func encoded() -> Data {
        var object: [String: Any] = ["version": Self.currentVersion, "mode": mode.rawValue]
        if let checked { object["checked"] = ISO8601DateFormatter().string(from: checked) }
        if let looked { object["looked"] = ISO8601DateFormatter().string(from: looked) }
        if let available { object["available"] = available }
        if !stopped.isEmpty { object["stopped"] = stopped }
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// Read the file. What it doesn't say, or says in a way this build doesn't know, is the default.
    ///
    /// - Parameter data: The file's bytes.
    /// - Returns: The state, or `nil` when it isn't a JSON object of a version this build reads.
    public init?(_ data: Data) {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let version = object["version"] as? Int, (1...Self.currentVersion).contains(version) else { return nil }
        mode = (object["mode"] as? String).flatMap(IndicatorPackMode.init(rawValue:)) ?? .notify
        checked = (object["checked"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
        looked = (object["looked"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
        available = object["available"] as? Int
        stopped = object["stopped"] as? [String: Int] ?? [:]
    }
}
