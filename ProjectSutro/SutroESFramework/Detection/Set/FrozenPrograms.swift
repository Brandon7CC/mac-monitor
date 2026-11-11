//
//  FrozenPrograms.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Frozen programs
/// A set's programs and its index by event type, laid end to end in buffers it allocates once and frees when the set
/// goes, so every lane evaluates them without touching a reference count: arrays would be retained and released on
/// each rule, and eight lanes doing that to one shared set's arrays fight over their cache lines.
///
/// A program's nodes name their children, and its comparisons their constants, by index, and its constants their
/// bytes, failure tables and strings by offset, so each is rebased by where its program starts. A program comes from
/// the compiler, or is copied out of another set's store, which is how a set made from another reuses its programs
/// without keeping a second copy of each.
///
/// **Threading:** immutable once made. Its owner frees it, once, in `deinit`.
struct FrozenPrograms {
    /// Where a program comes from.
    enum Origin {
        /// Just compiled.
        case compiled(IndicatorProgram)
        /// Another set's store's program, by its index there.
        case frozen(FrozenPrograms, Int)
    }

    /// Where one program's parts start in each buffer, and how many it has.
    struct Extent {
        /// Its nodes, constants, bytes, failure tables and strings, by position in each buffer.
        var nodes = 0..<0, constants = 0..<0, bytes = 0..<0, failures = 0..<0, strings = 0..<0
    }

    /// Each program's nodes, one program after another.
    private let nodes: Frozen<IndicatorProgram.Node>
    /// Each program's constants.
    private let constants: Frozen<IndicatorProgram.Constant>
    /// Each program's constants' bytes.
    private let bytes: Frozen<UInt8>
    /// Each program's failure tables.
    private let failures: Frozen<Int32>
    /// Each program's string constants, for Foundation's comparisons.
    private let strings: Frozen<NSString>
    /// Where each program is.
    private let extents: [Extent]
    /// Each program's root node.
    private let roots: Frozen<Int32>
    /// Each rule's program.
    private let rules: Frozen<Int32>
    /// Where each event type's rules start in ``typeRules``, by the type's number, and where the last ends.
    private let typeStarts: Frozen<Int32>
    /// The rules for each type in turn.
    private let typeRules: Frozen<Int32>

    /// - Parameters:
    ///   - origins: The distinct programs.
    ///   - rules: Each rule's program, by its index in `origins`, in order.
    ///   - byType: The rules for each event type, by the type's number.
    init(origins: [Origin], rules: [Int32], byType: [[Int32]]) {
        var parts = Parts()
        var extents: [Extent] = []
        extents.reserveCapacity(origins.count)
        for origin in origins {
            switch origin {
            case .compiled(let program):
                extents.append(parts.append(nodes: program.nodes, constants: program.constants, bytes: program.bytes,
                                            failures: program.failures, strings: program.strings, from: Extent()))
            case .frozen(let store, let index):
                let extent = store.extents[index]
                extents.append(parts.append(nodes: store.nodes.buffer[extent.nodes],
                                            constants: store.constants.buffer[extent.constants],
                                            bytes: store.bytes.buffer[extent.bytes],
                                            failures: store.failures.buffer[extent.failures],
                                            strings: store.strings.buffer[extent.strings], from: extent))
            }
        }
        nodes = Frozen(parts.nodes)
        constants = Frozen(parts.constants)
        bytes = Frozen(parts.bytes)
        failures = Frozen(parts.failures)
        strings = Frozen(parts.strings)
        self.extents = extents
        roots = Frozen(ContiguousArray(extents.map { Int32($0.nodes.lowerBound) }))
        self.rules = Frozen(ContiguousArray(rules))
        typeStarts = Frozen(ContiguousArray(byType.map(\.count).reductions(0).map(Int32.init)))
        typeRules = Frozen(ContiguousArray(byType.joined()))
    }

    /// The programs as they're evaluated.
    var view: IndicatorProgram.View {
        IndicatorProgram.View(nodes: nodes.buffer, constants: constants.buffer, bytes: bytes.buffer,
                              failures: failures.buffer, strings: strings.buffer)
    }

    /// How many event types it indexes.
    var typeCount: Int { typeStarts.buffer.count - 1 }

    /// How many nodes its programs have in all.
    var nodeCount: Int { nodes.buffer.count }

    /// The rules for an event type, as positions in ``typeRules``.
    ///
    /// - Parameter type: A type's number, below ``typeCount``.
    /// - Returns: The positions.
    @inline(__always)
    func slots(forType type: Int) -> Range<Int> {
        Int(typeStarts.buffer[type])..<Int(typeStarts.buffer[type + 1])
    }

    /// - Parameter slot: A position in ``typeRules``.
    /// - Returns: The rule there, by its index.
    @inline(__always)
    func rule(at slot: Int) -> Int {
        Int(typeRules.buffer[slot])
    }

    /// - Parameter rule: A rule's index.
    /// - Returns: Its program's root node.
    @inline(__always)
    func root(of rule: Int) -> Int {
        Int(roots.buffer[Int(rules.buffer[rule])])
    }

    /// Free every buffer. Call once, when nothing will read them again.
    func deallocate() {
        nodes.deallocate()
        constants.deallocate()
        bytes.deallocate()
        failures.deallocate()
        strings.deallocate()
        roots.deallocate()
        rules.deallocate()
        typeStarts.deallocate()
        typeRules.deallocate()
    }
}


// MARK: - Laying programs end to end
extension FrozenPrograms {
    /// The parts of the programs laid so far.
    private struct Parts {
        var nodes = ContiguousArray<IndicatorProgram.Node>(), constants = ContiguousArray<IndicatorProgram.Constant>()
        var bytes = ContiguousArray<UInt8>(), failures = ContiguousArray<Int32>(), strings = ContiguousArray<NSString>()

        /// Lay one program after the others, its indices and offsets rebased from where it was to where it goes.
        ///
        /// - Parameters:
        ///   - programNodes: Its nodes.
        ///   - programConstants: Its constants.
        ///   - programBytes: Its constants' bytes.
        ///   - programFailures: Its constants' failure tables.
        ///   - programStrings: Its constants' strings.
        ///   - old: Where it was: nothing for a program just compiled, which starts at 0.
        /// - Returns: Where it is now.
        mutating func append(nodes programNodes: some Collection<IndicatorProgram.Node>,
                             constants programConstants: some Collection<IndicatorProgram.Constant>,
                             bytes programBytes: some Collection<UInt8>,
                             failures programFailures: some Collection<Int32>,
                             strings programStrings: some Collection<NSString>, from old: Extent) -> Extent {
            let nodeShift = Int32(nodes.count - old.nodes.lowerBound)
            let constantShift = Int32(constants.count - old.constants.lowerBound)
            let byteShift = Int32(bytes.count - old.bytes.lowerBound)
            let failureShift = Int32(failures.count - old.failures.lowerBound)
            let stringShift = Int32(strings.count - old.strings.lowerBound)
            var extent = Extent()
            extent.nodes = nodes.count..<nodes.count + programNodes.count
            extent.constants = constants.count..<constants.count + programConstants.count
            extent.bytes = bytes.count..<bytes.count + programBytes.count
            extent.failures = failures.count..<failures.count + programFailures.count
            extent.strings = strings.count..<strings.count + programStrings.count
            nodes.append(contentsOf: programNodes.lazy.map { node in
                var node = node
                switch node.kind {
                case .and, .or, .not: node.first += nodeShift
                case .compare, .anyCompare, .eventType: node.first += constantShift
                case .truth: break
                }
                return node
            })
            constants.append(contentsOf: programConstants.lazy.map { constant in
                var constant = constant
                guard constant.kind == .string else { return constant }
                constant.offset += byteShift
                constant.string += stringShift
                if constant.failure >= 0 { constant.failure += failureShift }
                return constant
            })
            bytes.append(contentsOf: programBytes)
            failures.append(contentsOf: programFailures)
            strings.append(contentsOf: programStrings)
            return extent
        }
    }
}


// MARK: - Frozen buffers
/// A copy of an array in memory of its own, which stays put until it's freed: what a compiled set's programs
/// (``FrozenPrograms``) and its index (``IndicatorIndex``) are kept in, so lanes read them without a reference count.
struct Frozen<Element> {
    /// The copy.
    let buffer: UnsafeBufferPointer<Element>
    /// The memory, at least one element's.
    private let memory: UnsafeMutablePointer<Element>

    /// - Parameter array: The elements.
    init(_ array: ContiguousArray<Element>) {
        memory = .allocate(capacity: max(array.count, 1))
        _ = UnsafeMutableBufferPointer(start: memory, count: array.count).initialize(from: array)
        buffer = UnsafeBufferPointer(start: memory, count: array.count)
    }

    /// Free the copy.
    func deallocate() {
        memory.deinitialize(count: buffer.count)
        memory.deallocate()
    }
}


// MARK: - Running totals
private extension Sequence where Element == Int {
    /// - Parameter initial: The total before the first element.
    /// - Returns: The total before each element and after the last.
    func reductions(_ initial: Int) -> [Int] {
        var total = initial
        return [initial] + map { total += $0; return total }
    }
}
