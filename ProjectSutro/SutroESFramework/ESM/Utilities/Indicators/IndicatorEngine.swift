//
//  IndicatorEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import Combine
import OSLog


// MARK: - Indicator engine
/// Mac Monitor's side of the Mac's indicator set (agent context): the one set the Security Extension keeps and stamps
/// every captured event with (``SavedIndicatorSet``), asked for and changed over XPC (``IndicatorRequest``).
///
/// It publishes the set as the Security Extension last sent it, why it can't run some of them (``problems``), and
/// whether this Mac Monitor may change it (``canChangeIndicators``). Every change is a request. Its reply is the set
/// after it, so nothing is asked for afterwards. A request with no reply, from a Security Extension older than 3.1 or
/// none at all, leaves the set as it was and read-only (``Connection/unavailable``), with ``updateNotice``. There's no
/// timeout of its own: XPC's reply or error decides. Mac Monitor's transport sends nothing to a Security Extension
/// that hasn't said it answers (``SensorSupport``), since a request it doesn't know would close the connection.
///
/// The last set is kept in user defaults (``cacheKey``), for Open Trace, a missing Security Extension and an export's
/// fallback, read on any thread with ``cachedIndicators(in:)``. Without one, it's ``Indicator/defaults``.
///
/// **Threading:** use it on the main queue. The transport replies there.
public final class IndicatorEngine: ObservableObject {
    /// Sends an encoded ``IndicatorRequest`` and calls back on the main queue with the encoded ``IndicatorReply``, or
    /// `nil` when the request failed.
    public typealias Transport = (_ request: Data, _ reply: @escaping (Data?) -> Void) -> Void

    /// How the engine last heard from the Security Extension.
    public enum Connection: Equatable, Sendable {
        /// Nothing asked yet: the cached set shows.
        case waiting
        /// The Security Extension answered.
        case connected
        /// A request got no reply: the Security Extension is missing or older than 3.1.
        case unavailable
    }

    /// The user default that keeps the last set the Security Extension sent, as a JSON array of indicators.
    public static let cacheKey = "indicators.cache"
    /// The user default that keeps Mac Monitor's own indicators as the Security Extension last sent them, as a JSON
    /// array of indicators.
    public static let baselineCacheKey = "indicators.baseline.cache"
    /// The user default that keeps which indicator pack those are, by its sequence: 0 for a build's own.
    public static let packCacheKey = "indicators.pack.cache"
    /// Posted on the main queue by ``EndpointSecurityManager`` once the Security Extension answers a handshake: its
    /// indicators may have changed while it was away, so they're asked for again.
    public static let sensorReady = Notification.Name("IndicatorEngine.sensorReady")
    /// Shown while the Security Extension doesn't answer indicator requests.
    public static let updateNotice = """
        The Security Extension doesn't answer for this Mac's indicators. Update the Security Extension to see and \
        change them; until then, the indicators shown are the last it sent.
        """

    /// The set, in order, as the Security Extension last sent it, or the cache until it does.
    @Published public private(set) var indicators: [Indicator]
    /// Mac Monitor's own indicators as the Security Extension has them, which Restore Defaults brings back: this
    /// build's, until it says, and from one older than 3.2, which doesn't.
    @Published public private(set) var baseline: [Indicator] = Indicator.defaults
    /// Which release Mac Monitor's own indicators are, and whether a pack was installed since this build. `nil` until
    /// the Security Extension says, and from one older than 3.2.
    @Published public private(set) var pack: IndicatorPackStatus?
    /// A newer indicator pack the last look found, and what installing it would do. `nil` once it's installed, or
    /// when a later look finds none.
    @Published public private(set) var packOffer: IndicatorPackOffer?
    /// Is a look for a newer pack under way?
    @Published public private(set) var isLookingForPack = false
    /// Why the Security Extension can't run an indicator, by its identity.
    @Published public private(set) var problems: [UUID: String] = [:]
    /// How the engine last heard from the Security Extension.
    @Published public private(set) var connection: Connection = .waiting
    /// What this Mac Monitor may do with the set, as the Security Extension last said.
    @Published public private(set) var access: MuteAccess?
    /// Can nobody change the set? A newer Mac Monitor saved it.
    @Published public private(set) var isReadOnly = false
    /// Something to tell the user about the set: recovered, read-only, or ``updateNotice``.
    @Published public private(set) var notice: String?
    /// Why the last change was refused, or `nil` when it wasn't. Settings shows it and clears it.
    @Published public var failure: String?

    /// May this Mac Monitor change the set now? Only once the Security Extension answered, while it may write, and
    /// while the set isn't read-only.
    public var canChangeIndicators: Bool { connection == .connected && access == .write && !isReadOnly }

    private let defaults: UserDefaults
    private var transport: Transport?
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "IndicatorEngine")

    /// - Parameters:
    ///   - defaults: Where the last set is kept.
    ///   - transport: Sends requests to the Security Extension, or `nil` until ``connect(_:)``: until then, nothing
    ///     can change.
    public init(defaults: UserDefaults = .standard, transport: Transport? = nil) {
        self.defaults = defaults
        self.transport = transport
        indicators = Self.cachedIndicators(in: defaults)
    }

    /// - Parameter transport: Sends requests to the Security Extension from now on.
    public func connect(_ transport: @escaping Transport) {
        self.transport = transport
    }

    /// The last set the Security Extension sent, read on any thread, such as a search's worker.
    ///
    /// - Parameter defaults: Where it's kept.
    /// - Returns: It, or ``Indicator/defaults`` when none was kept or it can't be read.
    public static func cachedIndicators(in defaults: UserDefaults = .standard) -> [Indicator] {
        defaults.data(forKey: cacheKey).flatMap { try? JSONDecoder().decode([Indicator].self, from: $0) }
            ?? Indicator.defaults
    }

    /// Mac Monitor's own indicators as the Security Extension last sent them, read on any thread, such as an
    /// export's worker: what each hit Mac Monitor matches itself says it's a default of, or edited from.
    ///
    /// - Parameter defaults: Where they're kept.
    /// - Returns: Them, or ``Indicator/defaults`` when none were kept or they can't be read.
    public static func cachedBaseline(in defaults: UserDefaults = .standard) -> [Indicator] {
        defaults.data(forKey: baselineCacheKey).flatMap { try? JSONDecoder().decode([Indicator].self, from: $0) }
            ?? Indicator.defaults
    }

    /// Which indicator pack Mac Monitor's own indicators are, as the Security Extension last said, for the hits Mac
    /// Monitor matches itself (``RecordIndicators``).
    ///
    /// - Parameter defaults: Where it's kept.
    /// - Returns: The pack's sequence, or 0 when none was kept or they're a build's own.
    public static func cachedPack(in defaults: UserDefaults = .standard) -> Int {
        defaults.integer(forKey: packCacheKey)
    }

    // MARK: Requests

    /// Ask for the set again: when the Security Extension is ready, Settings > Indicators appears, or Mac Monitor
    /// becomes active, so changes `macmonitor` or another user made show.
    public func refresh() {
        send(IndicatorRequest(.list))
    }

    /// Send a request and publish the set it replies with.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - completion: Called on the main queue with the reply, or `nil` when there was none.
    public func send(_ request: IndicatorRequest, completion: ((IndicatorReply?) -> Void)? = nil) {
        guard let transport else {
            completion?(nil)
            return
        }
        let operation = request.operation
        transport(request.encoded()) { [weak self] data in
            guard let self else { return }
            guard let reply = data.flatMap(IndicatorReply.decode) else {
                logger.error("The indicator request (\(operation.rawValue, privacy: .public)) got no reply.")
                apply(nil, to: operation)
                completion?(nil)
                return
            }
            apply(reply, to: operation)
            completion?(reply)
        }
    }

    /// Publish what a request's reply says.
    ///
    /// - Parameters:
    ///   - reply: The reply, or `nil` when there was none.
    ///   - operation: What the request asked for: a list never sets ``failure``.
    private func apply(_ reply: IndicatorReply?, to operation: IndicatorRequest.Operation) {
        guard let reply else {
            connection = .unavailable
            notice = Self.updateNotice
            if operation != .list { failure = Self.updateNotice }
            return
        }
        connection = .connected
        access = reply.access
        isReadOnly = reply.readOnly || reply.status == .readOnly
        notice = reply.notice
        problems = Dictionary(reply.problems.map { ($0.id, $0.reason) }) { first, _ in first }
        if let shipped = reply.baseline, !shipped.isIdentical(to: baseline) {
            baseline = shipped
            defaults.set(try? JSONEncoder().encode(shipped), forKey: Self.baselineCacheKey)
        }
        if reply.pack != pack {
            pack = reply.pack
            defaults.set(reply.pack?.sequence ?? 0, forKey: Self.packCacheKey)
        }
        /// An install says how it went where it was asked for (``installPack(_:completion:)``).
        if operation != .list, operation != .installPack {
            failure = reply.status == .ok ? nil
                : reply.failure ?? "The Security Extension answered “\(reply.status.rawValue)”."
        }
        if let offer = packOffer, offer.sequence <= (reply.pack?.sequence ?? 0) { packOffer = nil }
        guard !reply.indicators.isIdentical(to: indicators) || defaults.data(forKey: Self.cacheKey) == nil
        else { return }
        indicators = reply.indicators
        defaults.set(try? JSONEncoder().encode(reply.indicators), forKey: Self.cacheKey)
    }
}


// MARK: - Changes
public extension IndicatorEngine {
    /// Add indicators, or replace those with their identities, in their place (``IndicatorRequest/Operation/add``):
    /// a new indicator, a Duplicate, an import, or a 3.0 import offer.
    ///
    /// - Parameters:
    ///   - indicators: The indicators.
    ///   - completion: Called with the reply, or `nil`.
    func add(_ indicators: [Indicator], completion: ((IndicatorReply?) -> Void)? = nil) {
        send(IndicatorRequest(.add, indicators: indicators), completion: completion)
    }

    /// Change some fields of indicators the set has (``IndicatorRequest/Operation/update``): an edit.
    ///
    /// - Parameters:
    ///   - indicators: The indicators, edited.
    ///   - fields: The fields to take from them.
    ///   - completion: Called with the reply, or `nil`.
    func update(_ indicators: [Indicator], fields: [Indicator.EditableField],
                completion: ((IndicatorReply?) -> Void)? = nil) {
        send(IndicatorRequest(.update, indicators: indicators, fields: fields), completion: completion)
    }

    /// Make the Mac's set have an indicator as Settings' editor or a row left it. A new one is added. Otherwise only
    /// what changed from the copy the editor opened with is sent: its switch, then the editable fields that differ.
    /// So another writer's change to anything else, such as `macmonitor` turning it off while the editor was open,
    /// stays, and one removed meanwhile is refused rather than brought back.
    ///
    /// - Parameters:
    ///   - edited: The indicator as edited. Its view switches are the user's (``IndicatorOverlay``), never sent.
    ///   - original: The indicator as the editor opened it, or `nil` for a new one.
    func change(_ edited: Indicator, from original: Indicator?) {
        guard let original else { return add([edited]) }
        if edited.isEnabled != original.isEnabled { setEnabled([edited.id], edited.isEnabled) }
        let fields = original.changedFields(to: edited)
        if !fields.isEmpty { update([edited], fields: fields) }
    }

    /// - Parameters:
    ///   - ids: The indicators to remove.
    ///   - completion: Called with the reply, or `nil`.
    func remove(_ ids: [UUID], completion: ((IndicatorReply?) -> Void)? = nil) {
        send(IndicatorRequest(.remove, ids: ids), completion: completion)
    }

    /// - Parameters:
    ///   - ids: The indicators to turn on or off.
    ///   - enabled: On or off.
    ///   - completion: Called with the reply, or `nil`.
    func setEnabled(_ ids: [UUID], _ enabled: Bool, completion: ((IndicatorReply?) -> Void)? = nil) {
        send(IndicatorRequest(.setEnabled, ids: ids, enabled: enabled), completion: completion)
    }

    /// Make the set the indicators the Security Extension ships again (``IndicatorRequest/Operation/reset``): its
    /// own list, not this app's, which differs when the two are different builds.
    ///
    /// - Parameter completion: Called with the reply, or `nil`.
    func restoreDefaults(completion: ((IndicatorReply?) -> Void)? = nil) {
        send(IndicatorRequest(.reset), completion: completion)
    }

    // MARK: Packs

    /// Have the Security Extension look on GitHub for a newer indicator pack, and say what installing it would do
    /// (``IndicatorRequest/Operation/checkPack``). Nothing is installed. The set shown stays the Mac's: the answer is
    /// kept as ``packOffer``, and the set is asked for again, for what the look left the Security Extension knowing.
    ///
    /// - Parameter completion: Called on the main queue with how the look went.
    func lookForPack(completion: ((IndicatorPackLook) -> Void)? = nil) {
        guard let transport, !isLookingForPack else {
            completion?(.failed(transport == nil ? Self.updateNotice : "A look is already under way."))
            return
        }
        isLookingForPack = true
        transport(IndicatorRequest(.checkPack).encoded()) { [weak self] data in
            guard let self else { return }
            isLookingForPack = false
            let look: IndicatorPackLook
            if let preview = data.flatMap(IndicatorReply.decode) {
                if let offer = IndicatorPackOffer(preview, over: indicators, pack: pack) {
                    look = .newer(offer)
                } else if preview.status == .ok {
                    look = .upToDate
                } else {
                    look = .failed(preview.failure
                                   ?? "The Security Extension answered “\(preview.status.rawValue)”.")
                }
            } else {
                look = .failed(Self.updateNotice)
            }
            if case .newer(let offer) = look { packOffer = offer } else if look == .upToDate { packOffer = nil }
            refresh()
            completion?(look)
        }
    }

    /// Install the pack a look offered, and only that release: one that came out since is refused, to be looked at
    /// first (``IndicatorRequest/expecting``).
    ///
    /// - Parameters:
    ///   - offer: The pack that was offered.
    ///   - completion: Called on the main queue with `nil` once it's installed, else why it wasn't.
    func installPack(_ offer: IndicatorPackOffer, completion: @escaping (String?) -> Void) {
        send(IndicatorRequest(.installPack, expecting: offer.sequence)) { reply in
            guard let reply else { return completion(Self.updateNotice) }
            guard reply.status == .ok else {
                return completion(reply.failure ?? "The Security Extension answered “\(reply.status.rawValue)”.")
            }
            /// Nothing changed when the pack was installed meanwhile, by someone else or the daily look.
            completion(reply.changed ? nil : "There's no newer indicator pack to install.")
        }
    }

    /// Change what the Security Extension does about newer indicator packs, for every user of this Mac.
    ///
    /// - Parameter mode: The mode.
    func setPackMode(_ mode: IndicatorPackMode) {
        send(IndicatorRequest(.setPackMode, mode: mode))
    }

    /// Is the set Mac Monitor's own, as the Security Extension has them (``baseline``), whatever the view switches
    /// each indicator has?
    var isDefault: Bool {
        guard indicators.count == baseline.count else { return false }
        return zip(indicators, baseline).allSatisfy { mine, shipped in
            var mine = mine
            mine.copyViews(from: shipped)
            return mine == shipped
        }
    }
}


// MARK: - Mac Monitor's connection
public extension EndpointSecurityManager {
    /// Sends indicator requests over Mac Monitor's own connection to the Security Extension, so it knows Mac Monitor
    /// as the app that owns the event stream, or not (``IndicatorEngine/connect(_:)``). A request waits until the
    /// Security Extension running now has said it answers them (``SensorSupport``). One that doesn't is sent
    /// nothing, and the request has no reply. One that stops answering is asked again before the next request.
    var indicatorTransport: IndicatorEngine.Transport {
        { [weak self] request, reply in
            guard let self else { return DispatchQueue.main.async { reply(nil) } }
            let sensor = sensor
            indicatorSupport.send({ answer in
                sensor.call { $0.indicators(request, reply: $1) } completion: { answer($0) }
            }, completion: reply)
        }
    }

    /// Ask the Security Extension running now for its indicators on a connection of its own
    /// (``SensorClient/probe(caller:_:completion:)``), for ``indicatorSupport``.
    ///
    /// - Parameter answered: Called on the main queue: `true` when it replied with a set.
    internal func probeIndicators(_ answered: @escaping (Bool) -> Void) {
        sensor.probe { $0.indicators(IndicatorRequest(.list).encoded(), reply: $1) } completion: { data in
            answered(data.flatMap(IndicatorReply.decode) != nil)
        }
    }
}
