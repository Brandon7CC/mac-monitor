//
//  FlowSourceTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - The source table
/// Every source one socket of the client reports, from its add to its removal, and the flows they become.
///
/// A TCP, QUIC or UDP subflow source becomes a flow once its remote end is known and it isn't listening. A UDP
/// socket is a flow only when it's removed, if it carried bytes to a known remote end that no subflow carried for it.
/// A flow open before the client started is adopted, and only its close is recorded. The kernel holds back most
/// loopback sources' updates. A loopback flow it still reports, or one past the rate budget, is skipped, so its close
/// isn't recorded either and no record is left without its pair.
///
/// A record's time is the descriptor copy time of the update it comes from, kept from going back.
///
/// **Threading:** not thread-safe. Only the client's read queue uses it.
final class FlowSourceTable {
    /// The most sources kept, about 20 MB with their details. Past it, new sources are counted and ignored.
    static let capacity = 16_384
    /// The most UDP subflows remembered, 24 bytes each. Past it, they're all forgotten.
    static let subflowCapacity = 65_536
    /// The most flows a second that open, past which they're skipped.
    static let budget = 200
    /// The table's storage is given back once it holds a quarter of what it has room for, above this many.
    private static let storageFloor = 1_024

    var counts = FlowCounts()
    /// The clocks of the read being handled.
    var clock: FlowClock
    /// The providers whose add failed, with the error, and the kinds of descriptor no layout fits yet.
    var providersOff: [NStat.Provider: Int32] = [:]
    private(set) var kindsOff = Set<DescriptorLayout.Kind>()
    var sources: [UInt64: FlowSource] = [:]
    /// The sources to query again, in the order they're due (``poll()``).
    var pollsDue = (soon: PollQueue(), later: PollQueue())
    /// Flows from the socket this one replaced, until their sources are seen again.
    var inherited: [FlowSource.Match: FlowSource] = [:]
    /// Set by each sign that the kernel dropped a message to the client. The client clears it.
    var lossSignalled = false

    /// Sends a query for a source's update, and says whether it was sent.
    let query: (NStat.Request) -> Bool
    private let resolver: FlowProcessResolver
    private let fallback: (DescriptorLayout.Kind) -> DescriptorLayout?
    /// Sources made before this tick existed before the client started.
    private let existingBefore: UInt64
    /// Takes each record.
    let emit: (FlowRecord) -> Void
    private var layouts: [DescriptorLayout.Kind: DescriptorLayout] = [:]
    private var lastSource: UInt64 = 0
    /// The last record's time, which no later record's goes before, and the second the rate budget counts in, with
    /// the flows opened in it.
    var lastTime = FlowTime(machTime: 0, wall: 0)
    var window: (start: TimeInterval, opened: Int) = (0, 0)
    /// When a UDP subflow was last seen for a process's local port, by unique ID and port.
    private var subflows: [SIMD2<UInt64>: UInt64] = [:]
    /// This process's pid, whose own flows are marked.
    static let ownPID = getpid()

    /// - Parameters:
    ///   - clock: The clocks when the socket opened.
    ///   - resolver: Tells which process a socket names.
    ///   - fallback: The descriptor layout to try when no known one fits.
    ///   - previous: The table of the socket this one replaces, whose flows and counts it carries on.
    ///   - query: Sends a query for a source's update.
    ///   - emit: Takes each record.
    init(clock: FlowClock, resolver: FlowProcessResolver,
         fallback: @escaping (DescriptorLayout.Kind) -> DescriptorLayout? = DescriptorEncoding.layout(of:),
         replacing previous: FlowSourceTable? = nil, query: @escaping (NStat.Request) -> Bool,
         emit: @escaping (FlowRecord) -> Void) {
        (self.clock, self.resolver, self.fallback) = (clock, resolver, fallback)
        (self.query, self.emit) = (query, emit)
        existingBefore = UInt64(clock.continuous)
        guard let previous else { return }
        (counts, layouts, lastTime, window) = (previous.counts, previous.layouts, previous.lastTime, previous.window)
        subflows = previous.subflows
        for source in previous.sources.values where source.details != nil { inherited[source.match] = source }
    }

    // MARK: Messages

    /// Take in one message from the kernel.
    ///
    /// - Parameters:
    ///   - header: Its header.
    ///   - message: The whole message.
    func handle(_ header: NStat.Header, _ message: UnsafeRawBufferPointer) {
        let reference: UInt64 = message.integer(at: NStat.Offset.source)
        switch NStat.MessageType(rawValue: header.type) {
        case .sourceAdded:
            add(reference, provider: message.integer(at: NStat.Offset.addedProvider))
        case .sourceUpdate, .sourceExtendedUpdate:
            update(reference, header, message, provider: message.integer(at: NStat.Offset.updateProvider),
                   at: NStat.Offset.updateDescriptor)
        case .sourceDescription where header.has(NStat.closing):
            update(reference, header, message, provider: message.integer(at: NStat.Offset.descriptionProvider),
                   at: NStat.Offset.descriptionDescriptor)
        case .sourceCounts where header.has(NStat.closing):
            sources[reference]?.received = message.integer(at: NStat.Offset.receivedBytes)
            sources[reference]?.sent = message.integer(at: NStat.Offset.sentBytes)
        case .sourceRemoved:
            remove(reference, header)
        case .error:
            failed(NStat.Request(context: header.context), errno: message.integer(at: NStat.Offset.error))
        default:
            break
        }
    }

    /// A source was added. Query its update at once, while its process is still there.
    ///
    /// - Parameters:
    ///   - reference: Its source reference.
    ///   - provider: Its provider.
    private func add(_ reference: UInt64, provider: UInt32) {
        note(reference)
        guard let provider = NStat.Provider(rawValue: provider), sources[reference] == nil else { return }
        guard sources.count < Self.capacity else {
            counts.ignoredSources += 1
            return
        }
        sources[reference] = FlowSource(provider: provider)
        if !query(.query(reference)) { queryFailed(reference) }
    }

    /// An update, or a legacy closing description, came for a source.
    ///
    /// - Parameters:
    ///   - reference: Its source reference.
    ///   - header: The message's header.
    ///   - message: The message.
    ///   - provider: Its provider.
    ///   - offset: Where its descriptor is.
    private func update(_ reference: UInt64, _ header: NStat.Header, _ message: UnsafeRawBufferPointer,
                        provider: UInt32, at offset: Int) {
        guard let provider = NStat.Provider(rawValue: provider),
              let layout = layout(provider.kind, message, at: offset),
              let descriptor = FlowDescriptor(message, at: offset, layout: layout) else {
            counts.malformed += 1
            return
        }
        guard var source = sources[reference] ?? late(reference, provider) else { return }
        let first = source.details == nil, closing = header.has(NStat.closing)
        if descriptor.local.isKnown { source.local = descriptor.local }
        if descriptor.remote.isKnown { source.remote = descriptor.remote }
        (source.state, source.ifnetProperties) = (descriptor.state, descriptor.ifnetProperties)
        let matched = first && describe(&source, descriptor)
        // A source's items are read at each update while it's pending and has none, since a kernel socket can
        // connect at a later update than its first.
        if let details = source.details, details.items.isEmpty, first || closing || source.stage == .pending,
           header.type == NStat.MessageType.sourceExtendedUpdate.rawValue {
            let items = UnsafeRawBufferPointer(rebasing: message[(offset + layout.size)...])
            details.items = FlowItems.read(items: items, provider: provider)
        }
        if offset == NStat.Offset.updateDescriptor {
            (source.received, source.sent) = (message.integer(at: NStat.Offset.receivedBytes),
                                              message.integer(at: NStat.Offset.sentBytes))
        }
        if closing { source.closedAt = descriptor.timestamp }
        if provider == .udpSubflow || provider == .udpUserland, source.local.port != 0 {
            if subflows.count >= Self.subflowCapacity { subflows.removeAll(keepingCapacity: true) }
            subflows[SIMD2(source.upid, UInt64(source.local.port))] = descriptor.timestamp
        }
        if source.stage == .pending, provider != .udpKernel, source.remote.isKnown, !source.isListener {
            // A source seen again after a reopen was adopted or not at its first update before it.
            open(&source, at: descriptor.timestamp, first: first && !matched)
        } else if first, source.stage == .pending, provider == .tcpKernel, !source.isListener {
            schedulePoll(&source, reference)
        }
        sources[reference] = source
    }

    /// The layout of a kind's descriptor, detected from the first message that fits, and kept.
    ///
    /// - Parameters:
    ///   - kind: The kind.
    ///   - message: A whole message.
    ///   - offset: Where its descriptor is.
    /// - Returns: The layout, or `nil` while none fits.
    private func layout(_ kind: DescriptorLayout.Kind, _ message: UnsafeRawBufferPointer,
                        at offset: Int) -> DescriptorLayout? {
        if let layout = layouts[kind] { return layout }
        guard let layout = DescriptorLayout.detect(kind, message, at: offset, fallback: fallback) else {
            kindsOff.insert(kind)
            return nil
        }
        kindsOff.remove(kind)
        layouts[kind] = layout
        return layout
    }

    /// Count the source references skipped before this one. The kernel uses one up even when it couldn't queue the
    /// add.
    ///
    /// - Parameter reference: A source's reference, from its add or its first message.
    private func note(_ reference: UInt64) {
        guard reference > lastSource else { return }
        let gap = reference &- lastSource &- 1
        if gap > 0 {
            // A gap of billions is a damaged message, not lost sockets.
            counts.lostSources += Int(min(gap, 1 << 32))
            lossSignalled = true
        }
        lastSource = reference
    }

    /// A source whose add was lost, made from its first message. Its own lost add is a loss too.
    ///
    /// - Parameters:
    ///   - reference: Its source reference.
    ///   - provider: Its provider.
    /// - Returns: The source, or `nil` when the table is full.
    private func late(_ reference: UInt64, _ provider: NStat.Provider) -> FlowSource? {
        // One the table already counted, as lost or ignored, isn't a new loss.
        let isNew = reference > lastSource
        note(reference)
        guard sources.count < Self.capacity else {
            if isNew { counts.ignoredSources += 1 }
            return nil
        }
        if isNew { lossSignalled = true }
        counts.lateSources += 1
        return FlowSource(provider: provider)
    }

    /// Read a source's first update, for whether it's one from the socket this one replaced, and its process.
    /// A loopback source is never recorded, so nothing is read of its process. A local storm costs only the parse.
    ///
    /// - Parameters:
    ///   - source: The source, with its first update's ends.
    ///   - descriptor: Its descriptor.
    /// - Returns: Whether it's one from the socket this one replaced, which keeps its stage and identifier.
    private func describe(_ source: inout FlowSource, _ descriptor: FlowDescriptor) -> Bool {
        (source.upid, source.start) = (descriptor.upid, descriptor.start)
        let earlier = inherited.removeValue(forKey: source.match)
        if let earlier {
            (source.stage, source.identifier, source.isExisting) = (earlier.stage, earlier.identifier,
                                                                    earlier.isExisting)
        } else {
            source.isExisting = descriptor.start < existingBefore
        }
        let details: FlowSource.Details
        if source.isLoopback {
            details = FlowSource.Details(process: FlowProcess(pid: descriptor.pid, name: "", state: .reaped))
        } else {
            /// A socket no process has used since it was made names pid 0, and its owner as the effective pid.
            let unused = descriptor.pid == 0 && descriptor.epid > 0
            let process = unused
                ? resolver.resolve(pid: descriptor.epid, upid: descriptor.eupid, name: "")
                : resolver.resolve(pid: descriptor.pid, upid: descriptor.upid, name: descriptor.processName())
            if process.state == .zombie { counts.zombies += 1 }
            let acting = !unused && descriptor.epid != 0 && descriptor.epid != descriptor.pid
            details = FlowSource.Details(process: process, sourceApp: acting ? resolver.resolve(
                pid: descriptor.epid, upid: descriptor.eupid, name: "") : nil)
        }
        details.items = earlier?.details?.items ?? FlowItems()
        source.details = details
        return earlier != nil
    }

    /// A source was removed, so its flow closes. A UDP socket becomes a flow now, if it ever will.
    ///
    /// - Parameters:
    ///   - reference: Its source reference.
    ///   - header: The removal's header. It says whether the source closed after a message to the client was
    ///     dropped, or after the filter held back its closing update.
    private func remove(_ reference: UInt64, _ header: NStat.Header) {
        if header.has(NStat.closedAfterDrop) {
            counts.closedAfterDrop += 1
            lossSignalled = true
        }
        guard var source = take(reference) else { return }
        let subflow = subflows[SIMD2(source.upid, UInt64(source.local.port))] ?? 0
        if source.provider == .udpKernel, source.stage == .pending, source.remote.isKnown,
           source.received > 0 || source.sent > 0, subflow < source.start || subflow == 0 {
            open(&source, at: source.closedAt ?? 0, first: true)
        }
        close(source, wentLocal: header.has(NStat.closedAfterFilter))
    }

    /// The kernel answered a request with an error.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - errno: The error.
    private func failed(_ request: NStat.Request?, errno: Int32) {
        switch (request, errno) {
        case (.add(let provider), _):
            providersOff[provider] = errno
        case (.query(let reference), ENOBUFS), (.query(let reference), ENOMEM):
            counts.queryFailures += 1
            queryFailed(reference)
        case (.query(let reference), ENOENT):
            // The kernel no longer has the source, or its filter holds it back, so it isn't polled again.
            sources[reference]?.nextPoll = .infinity
        case (.check, ENOBUFS), (.check, ENOMEM):
            counts.queryFailures += 1
        case (.check(let reference), ENOENT):
            if let source = take(reference) { close(source) }
        default:
            break
        }
    }

    /// Take a source out of the table. Once the table is mostly empty its storage is given back, or a storm of
    /// sockets would keep it at its largest for good.
    ///
    /// - Parameter reference: Its source reference.
    /// - Returns: The source, or `nil` when the table didn't have it.
    private func take(_ reference: UInt64) -> FlowSource? {
        let source = sources.removeValue(forKey: reference)
        if sources.capacity > Self.storageFloor, sources.count < sources.capacity / 4 {
            var smaller = [UInt64: FlowSource](minimumCapacity: sources.count * 2)
            smaller.merge(sources) { kept, _ in kept }
            sources = smaller
        }
        return source
    }
}
