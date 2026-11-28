//
//  NetworkStatisticsClient.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import os


// MARK: - The network statistics client
/// Reads every network flow from the kernel's network statistics socket, `com.apple.network.statistics`, as root
/// (Security Extension context), and hands each flow that opens or closes to its consumers (``FlowRecord``).
///
/// Capture sessions share one (``shared``). The first consumer opens the socket and the last closes it, so nothing
/// is read while no session records flows. A consumer the socket couldn't be opened for isn't kept.
///
/// **Threading:** thread-safe. Two serial queues do the work. The read queue reads the socket, keeps the sources,
/// and reads each new flow's process, and never waits on anything outside it. The delivery queue completes each
/// record's process from the lineage table, the one wait, which is budgeted, and calls each consumer's
/// ``FlowConsumer/handle(_:)`` in turn. Nothing a consumer does holds the read queue up. While it's busy the
/// socket's 4 MB buffer holds what comes, and past that the kernel's drops are counted.
public final class NetworkStatisticsClient: @unchecked Sendable {
    /// The one the Security Extension's capture sessions share.
    public static let shared = NetworkStatisticsClient()

    /// The most datagrams read per wake. The read source fires again when more are waiting.
    static let readLimit = 1_024
    /// The most flows whose opening's completed processes are kept for their close.
    static let completedLimit = 1_024
    /// The read buffer, and what it grows to once a datagram didn't fit.
    static let smallBuffer = 64 << 10, largeBuffer = 1 << 20

    let readQueue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.flows.read",
                                  qos: .userInitiated)
    private let deliveryQueue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.flows.deliver",
                                              qos: .utility)
    /// Every consumer, in the order they registered.
    let consumers = OSAllocatedUnfairLock(uncheckedState: [FlowConsumer]())
    /// Reaped processes the lineage table didn't know, counted on the delivery queue.
    private let unresolved = OSAllocatedUnfairLock(initialState: 0)
    let makeSocket: () throws -> FlowSocket
    let resolver: FlowProcessResolver
    private let fallback: (DescriptorLayout.Kind) -> DescriptorLayout?
    private let lineage: () -> ProcessLineage?
    let clock: () -> FlowClock
    let addFailures: () -> UInt32?
    let darwin: Int
    /// Does a timer wake the client for what's due? Tests drain instead, on a clock they move.
    private let wakes: Bool

    // Only touched on the read queue.
    var socket: FlowSocket?
    var table: FlowSourceTable?
    /// The state, reason and buffer sizes, which the table doesn't keep.
    var current = FlowClientStatus()
    var loss = LossState()
    private var buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: smallBuffer, alignment: 8)
    private var timer: DispatchSourceTimer?
    /// The processes a flow's opening was delivered with, by flow, when the lineage table had to complete them. Its
    /// close is delivered with the same, so both records name one program. Only touched on the delivery queue.
    private var completed: [UUID: (process: FlowProcess, sourceApp: FlowProcess?, resolved: Bool)] = [:]

    /// - Parameters:
    ///   - socket: Opens the socket.
    ///   - resolver: Tells which process a socket names.
    ///   - fallback: The descriptor layout to try when no known one fits.
    ///   - lineage: The lineage table, while it's told of events.
    ///   - clock: Reads the clocks.
    ///   - addFailures: Reads the kernel's count of adds it couldn't queue for any client.
    ///   - darwin: This Mac's Darwin major version.
    ///   - wakes: Wake on a timer for what's due?
    init(socket: @escaping () throws -> FlowSocket = { try KernelFlowSocket() },
         resolver: FlowProcessResolver = FlowProcessResolver(),
         fallback: @escaping (DescriptorLayout.Kind) -> DescriptorLayout? = DescriptorEncoding.layout(of:),
         lineage: @escaping () -> ProcessLineage? = { LineageMonitor.shared.table },
         clock: @escaping () -> FlowClock = FlowClock.now, addFailures: @escaping () -> UInt32? = NStat.addFailures,
         darwin: Int = NStat.darwinMajor, wakes: Bool = true) {
        (makeSocket, self.resolver, self.fallback, self.lineage) = (socket, resolver, fallback, lineage)
        (self.clock, self.addFailures, self.darwin, self.wakes) = (clock, addFailures, darwin, wakes)
    }

    deinit {
        timer?.cancel()
        socket?.close()
        buffer.deallocate()
    }

    // MARK: Consumers

    /// Add a consumer. The first opens the socket before this returns.
    ///
    /// The counts are read in the same step as the decision to open, so they belong to the socket the consumer is
    /// on. A socket it opens has none.
    ///
    /// - Parameter consumer: The consumer.
    /// - Returns: The state after, why it's unavailable, and the counts as the consumer joined. `.unavailable` when
    ///   the socket couldn't be opened. The consumer then isn't kept, and the next registration tries again.
    @discardableResult
    func register(_ consumer: FlowConsumer) -> (state: FlowClientStatus.State, reason: String?, counts: FlowCounts) {
        consumers.withLock { $0.append(consumer) }
        let joined = readQueue.sync { [self] in
            let counts = table?.counts ?? FlowCounts()
            return (state: reconcile(), reason: current.reason, counts: counts)
        }
        if joined.state == .unavailable { consumers.withLock { $0.removeAll { $0 === consumer } } }
        return joined
    }

    /// Remove a consumer. The last closes the socket and empties the table.
    ///
    /// - Parameter consumer: The consumer.
    /// - Returns: The counts as it left, read in the same step as the decision to close.
    @discardableResult
    func unregister(_ consumer: FlowConsumer) -> FlowCounts {
        consumers.withLock { $0.removeAll { $0 === consumer } }
        return readQueue.sync { [self] in
            let counts = table?.counts ?? FlowCounts()
            _ = reconcile()
            return counts
        }
    }

    /// Read what's waiting, deliver it, then call back.
    ///
    /// - Parameter completion: Called on the delivery queue once everything read so far is delivered.
    func drain(_ completion: @escaping () -> Void) {
        readQueue.async { [self] in
            readAvailable()
            deliveryQueue.async(execute: completion)
        }
    }

    /// The client's status, as of the read queue's last message.
    public var status: FlowClientStatus {
        var status = readQueue.sync { [self] in
            var status = current
            guard let table else { return status }
            status.counts = table.counts
            status.openSources = table.sources.count
            status.flows = table.openFlows().count
            for (provider, error) in table.providersOff {
                status.providersOff["\(provider)"] = String(cString: strerror(error))
            }
            for provider in NStat.Provider.allCases where table.kindsOff.contains(provider.kind) {
                status.providersOff["\(provider)"] = "No descriptor layout fits its updates."
            }
            return status
        }
        status.counts.unresolved = unresolved.withLock { $0 }
        return status
    }

    /// Open the socket while there are consumers, and close it once there are none. Decided from the consumers as
    /// they are when it runs, so a last removal followed at once by an addition leaves the socket open. Call on the
    /// read queue.
    ///
    /// - Returns: The state after.
    private func reconcile() -> FlowClientStatus.State {
        let wanted = !consumers.withLock { $0.isEmpty }
        if wanted, socket == nil {
            open()
        } else if !wanted, socket != nil {
            close()
        }
        return current.state
    }

    // MARK: The socket

    /// Open the socket, ask for every source, and start reading. Call on the read queue.
    private func open() {
        let made: FlowSocket
        do {
            made = try makeSocket()
        } catch {
            current = FlowClientStatus()
            (current.state, current.reason) = (.unavailable, "\(error)")
            return
        }
        current = FlowClientStatus()
        (current.state, current.receiveBuffer) = (.on, made.receiveBuffer)
        let clock = clock(), refused = subscribe(made)
        let table = makeTable(clock: clock, replacing: nil)
        table.providersOff = refused
        start(made, table: table)
        if wakes {
            let timer = DispatchSource.makeTimerSource(queue: readQueue)
            timer.setEventHandler { [weak self] in self?.tick() }
            timer.schedule(deadline: .distantFuture)
            timer.resume()
            self.timer = timer
        }
        tick()
    }

    /// Close the socket and forget everything. Flows still open get no close. Call on the read queue.
    private func close() {
        timer?.cancel()
        socket?.close()
        (timer, socket, table, loss) = (nil, nil, nil, LossState())
        resolver.removeAll()
        unresolved.withLock { $0 = 0 }
        deliveryQueue.async { [self] in completed = [:] }
        current = FlowClientStatus()
    }

    /// Ask a new socket for every source. First a query puts it in updates mode, so closing sources send an
    /// update with their final counts. Then each provider is added, with a filter that holds back loopback sources'
    /// updates (``NStat/Provider/filter(darwin:)``). Kernel TCP asks for an update at connect where the kernel has
    /// that event. Call on the read queue.
    ///
    /// - Parameter socket: The socket.
    /// - Returns: The providers whose add failed with no error to read, since the kernel couldn't queue that
    ///   either, with the errno.
    func subscribe(_ socket: FlowSocket) -> [NStat.Provider: Int32] {
        _ = NStat.getUpdate(0, context: NStat.Request.mode.context) { socket.send($0) }
        var refused: [NStat.Provider: Int32] = [:]
        for provider in NStat.Provider.allCases {
            let events = provider == .tcpKernel && darwin >= 23 ? NStat.flowStateOutbound : 0
            let error = NStat.addAll(provider.rawValue, filter: provider.filter(darwin: darwin), events: events,
                                     context: NStat.Request.add(provider).context) { socket.send($0) }
            if error != 0 { refused[provider] = error }
        }
        return refused
    }

    /// Start reading a socket into a table. Call on the read queue.
    ///
    /// - Parameters:
    ///   - socket: The socket.
    ///   - table: Its table.
    func start(_ socket: FlowSocket, table: FlowSourceTable) {
        (self.socket, self.table) = (socket, table)
        socket.startReading(on: readQueue) { [weak self] in self?.readAvailable() }
    }

    /// A table for a socket.
    ///
    /// - Parameters:
    ///   - clock: The clocks when the socket was asked for every source.
    ///   - previous: The table of the socket it replaces.
    /// - Returns: The table.
    func makeTable(clock: FlowClock, replacing previous: FlowSourceTable?) -> FlowSourceTable {
        FlowSourceTable(clock: clock, resolver: resolver, fallback: fallback, replacing: previous,
                        query: { [unowned self] in send($0) }, emit: { [unowned self] in deliver($0) })
    }

    /// Send a source's query on the open socket. Call on the read queue.
    ///
    /// - Parameter request: The query.
    /// - Returns: Whether it was sent.
    func send(_ request: NStat.Request) -> Bool {
        switch (request, socket) {
        case (.query(let reference), let socket?), (.check(let reference), let socket?):
            return NStat.getUpdate(reference, context: request.context) { socket.send($0) } == 0
        default:
            return false
        }
    }

    // MARK: Reading

    /// Read what's waiting, then do what's due. Call on the read queue.
    func readAvailable() {
        readDatagrams()
        tick()
    }

    /// Read what's waiting. A datagram cut short may have held a removal, so it's a sign of loss. Call on the read
    /// queue.
    ///
    /// - Parameter limit: The most datagrams to read.
    func readDatagrams(limit: Int = readLimit) {
        guard let socket, let table else { return }
        table.clock = clock()
        current.bufferHighWater = max(current.bufferHighWater, socket.pending())
        for _ in 0..<limit {
            var truncated = false
            let length = socket.receive(into: buffer, truncated: &truncated)
            guard length > 0 else { break }
            if truncated {
                table.counts.truncated += 1
                table.lossSignalled = true
                if buffer.count < Self.largeBuffer {
                    buffer.deallocate()
                    buffer = .allocate(byteCount: Self.largeBuffer, alignment: 8)
                    continue
                }
            }
            process(datagram: UnsafeRawBufferPointer(rebasing: buffer[..<length]))
        }
    }

    /// Take in one datagram. One whose messages can't all be walked may have held a removal, so it's a sign of
    /// loss. Call on the read queue.
    ///
    /// - Parameter datagram: The datagram.
    func process(datagram: UnsafeRawBufferPointer) {
        guard let table, !NStat.forEachMessage(in: datagram, table.handle) else { return }
        table.counts.malformed += 1
        table.lossSignalled = true
    }

    /// Do what's due, the polls, the loss check and the add failure check. Then wake again when the next is due. Call
    /// on the read queue.
    func tick() {
        guard let table else { return }
        table.clock = clock()
        let now = table.clock.seconds
        let sending = (socket?.pending() ?? 0) < Self.checkBelow
        let next = table.poll(sending: sending).earlier(checkLosses(now)).earlier(checkAddFailures(now))
        timer?.schedule(deadline: next.map { .now() + max($0 - now, 0) } ?? .distantFuture)
    }

    /// Hand a record to the delivery queue, which completes its process from the lineage table, then gives it to
    /// every consumer.
    ///
    /// - Parameter record: The record.
    private func deliver(_ record: FlowRecord) {
        deliveryQueue.async { [self] in
            var record = record
            if !complete(&record) { unresolved.withLock { $0 += 1 } }
            for consumer in consumers.withLock({ $0 }) { consumer.handle(record) }
        }
    }

    /// Complete a record's processes from the lineage table. A flow's close takes what its opening got. Call on
    /// the delivery queue.
    ///
    /// - Parameter record: The record.
    /// - Returns: `false` for a reaped process the lineage table doesn't know.
    private func complete(_ record: inout FlowRecord) -> Bool {
        if let done = completed.removeValue(forKey: record.identifier) {
            (record.process, record.sourceApp) = (done.process, done.sourceApp)
            return done.resolved
        }
        let settled = record.process.isSettled && record.sourceApp?.isSettled != false
        let table = lineage(), time = record.time.machTime
        let resolved = table.map { record.process.complete(from: $0, upTo: time) } ?? (record.process.state != .reaped)
        if let table { _ = record.sourceApp?.complete(from: table, upTo: time) }
        if record.kind == .opened, !settled {
            if completed.count >= Self.completedLimit { completed = [:] }
            completed[record.identifier] = (record.process, record.sourceApp, resolved)
        }
        return resolved
    }
}
