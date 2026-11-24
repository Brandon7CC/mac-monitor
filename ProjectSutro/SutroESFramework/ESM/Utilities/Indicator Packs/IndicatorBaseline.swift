//
//  IndicatorBaseline.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - Indicator baseline
/// The indicators Mac Monitor ships, which the Mac's set is saved against (``SavedIndicators``): the signed pack this
/// build links in (``LinkedIndicatorPack``), or one installed since (``IndicatorPack``), whichever is the later
/// release.
///
/// The set saves only what someone changed on top of the baseline. A pack installed later then changes, adds or
/// drops an indicator for everyone who didn't edit it, as a new build does.
public struct IndicatorBaseline: Equatable {
    /// Where a baseline's indicators come from.
    public enum Source: String, Codable, Sendable {
        /// This build links them in.
        case linked
        /// A signed pack installed after this build was.
        case installed
    }

    /// Where its indicators come from.
    public let source: Source
    /// Which release of the indicators it is. A pack's goes up by one with every release, and 0 is a build's own
    /// indicators, which aren't a release.
    public let sequence: Int
    /// Its indicators, in order. One that needs a newer Mac Monitor is here, but isn't run.
    public let indicators: [Indicator]
    /// When its pack's commit was made, such as `2026-11-15T09:35:16Z`. `nil` for a build's own indicators.
    public let published: String?
    /// The indicators repository's commit its pack was built from. `nil` for a build's own indicators.
    public let commit: String?
    /// The entries of its pack this build can't read, which need a newer Mac Monitor.
    public let newer: [IndicatorPack.Newer]
    /// The identities never used again: a saved reference to one is dropped (``SavedIndicators``).
    public let retired: Set<UUID>

    /// The pack this build links in (``LinkedIndicatorPack``).
    public static let linked = IndicatorBaseline(linked: LinkedIndicatorPack.pack)

    /// - Parameters:
    ///   - indicators: The indicators a build links in.
    ///   - sequence: Which release they are: 0 unless they're a pack's.
    ///   - retired: The identities never used again: those Mac Monitor 3.1 stopped shipping, unless given.
    public init(linked indicators: [Indicator], sequence: Int = 0,
                retired: Set<UUID> = Indicator.retiredDefaults) {
        source = .linked
        self.sequence = sequence
        self.indicators = indicators
        published = nil
        commit = nil
        newer = []
        self.retired = retired
    }

    /// - Parameter pack: The pack a build links in.
    init(linked pack: IndicatorPack) {
        self.init(installed: pack, source: .linked)
    }

    /// - Parameters:
    ///   - pack: An installed pack, verified and read.
    ///   - source: Where it comes from: installed unless given.
    public init(installed pack: IndicatorPack, source: Source = .installed) {
        self.source = source
        sequence = pack.pack.sequence
        indicators = pack.indicators
        published = pack.pack.published
        commit = pack.pack.commit
        newer = pack.newer
        retired = Set(pack.pack.retired)
    }

    /// The baseline a verified pack makes, when it may take this one's place: its payload is a pack this build reads
    /// (``IndicatorPack/decode(_:)``), and a later release than this one. An equal or older one is refused, so a
    /// pack that was signed once can't be installed again to bring back a rule a later one fixed.
    ///
    /// - Parameter payload: The pack's payload, exactly as signed (``VerifiedIndicatorPack/payload``).
    /// - Returns: The pack as a baseline.
    /// - Throws: ``IndicatorPackRefusal/payload(_:)`` or ``IndicatorPackRefusal/notNewer(offered:current:source:)``.
    public func replacement(from payload: Data) throws(IndicatorPackRefusal) -> IndicatorBaseline {
        let pack: IndicatorPack
        do {
            pack = try IndicatorPack.decode(payload)
        } catch {
            throw .payload(error.description)
        }
        guard pack.pack.sequence > sequence else {
            throw .notNewer(offered: pack.pack.sequence, current: sequence, source: source)
        }
        return IndicatorBaseline(installed: pack)
    }

    /// What a reply says about it.
    ///
    /// - Parameter linked: The release this build links in, the floor.
    /// - Returns: The status.
    func status(linked: Int) -> IndicatorPackStatus {
        IndicatorPackStatus(sequence: sequence, source: source, published: published, commit: commit, linked: linked,
                            needsNewer: newer.count + indicators.count(where: { !$0.isSupported }))
    }
}


// MARK: - Pack status
/// Which indicators Mac Monitor's own are, as the Security Extension tells Mac Monitor and `macmonitor`
/// (``IndicatorReply/pack``).
public struct IndicatorPackStatus: Codable, Equatable, Sendable {
    /// Which release they are: a pack's sequence, or 0 for a build's own indicators.
    public var sequence: Int
    /// Whether the build links them in, or a pack was installed since.
    public var source: IndicatorBaseline.Source
    /// When the pack's commit was made, as the pack says it.
    public var published: String?
    /// The indicators repository's commit the pack was built from.
    public var commit: String?
    /// The release this build links in: the floor a pack must be later than to be installed.
    public var linked: Int
    /// How many of its indicators need a newer Mac Monitor, and aren't run.
    public var needsNewer: Int
    /// What the Security Extension does about newer packs. `nil` when it didn't say.
    public var mode: IndicatorPackMode?
    /// When GitHub was last asked for a newer pack, in ISO 8601. `nil` when it never was.
    public var checked: String?
    /// The sequence of a newer pack the last look found, which isn't installed. `nil` for none.
    public var available: Int?
    /// Why the last look found nothing it could use, as the user reads it. `nil` when it went well.
    public var problem: String?

    /// - Parameters:
    ///   - sequence: Which release they are.
    ///   - source: Whether the build links them in, or a pack was installed since.
    ///   - published: When the pack's commit was made.
    ///   - commit: The commit the pack was built from.
    ///   - linked: The release this build links in.
    ///   - needsNewer: How many need a newer Mac Monitor.
    ///   - mode: What the Security Extension does about newer packs.
    ///   - checked: When GitHub was last asked for a newer pack.
    ///   - available: The sequence of a newer pack that isn't installed.
    ///   - problem: Why the last look found nothing it could use.
    public init(sequence: Int, source: IndicatorBaseline.Source, published: String? = nil, commit: String? = nil,
                linked: Int = 0, needsNewer: Int = 0, mode: IndicatorPackMode? = nil, checked: String? = nil,
                available: Int? = nil, problem: String? = nil) {
        self.sequence = sequence
        self.source = source
        self.published = published
        self.commit = commit
        self.linked = linked
        self.needsNewer = needsNewer
        self.mode = mode
        self.checked = checked
        self.available = available
        self.problem = problem
    }

    /// Only the release and where it comes from have to be there. What a newer Security Extension says in a way this
    /// build doesn't know, such as another mode, is left out.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: A `DecodingError` for a missing sequence or source, or a source this build doesn't know.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = try container.decode(Int.self, forKey: .sequence)
        source = try container.decode(IndicatorBaseline.Source.self, forKey: .source)
        published = try? container.decodeIfPresent(String.self, forKey: .published)
        commit = try? container.decodeIfPresent(String.self, forKey: .commit)
        linked = (try? container.decodeIfPresent(Int.self, forKey: .linked)) ?? 0
        needsNewer = (try? container.decodeIfPresent(Int.self, forKey: .needsNewer)) ?? 0
        mode = try? container.decodeIfPresent(IndicatorPackMode.self, forKey: .mode)
        checked = try? container.decodeIfPresent(String.self, forKey: .checked)
        available = try? container.decodeIfPresent(Int.self, forKey: .available)
        problem = try? container.decodeIfPresent(String.self, forKey: .problem)
    }
}
