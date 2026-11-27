//
//  RecordPathTrie+Walk.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Walking an event's encoding
/// What one walk found.
final class RecordWalk {
    let trie: RecordPathTrie
    /// The scalars found, by node.
    var found: [(Int32, IndicatorValue)] = []
    /// The arrays of strings found, by node.
    var arrays: [Int32: [String]] = [:]
    /// The leaves whose values were worked out as the record writes them, which the encoding's own don't replace.
    var derived = Set<Int32>()

    /// - Parameter trie: The fields to find.
    init(_ trie: RecordPathTrie) {
        self.trie = trie
        found.reserveCapacity(trie.fields.count)
    }

    /// Keep a leaf's scalar.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - node: Where it was met.
    @inline(__always)
    func note(_ value: IndicatorValue, at node: Int32) {
        guard trie.isLeaf(node), derived.isEmpty || !derived.contains(node) else { return }
        found.append((node, value))
    }

    /// Note an array of strings met at a leaf, which its elements are added to.
    ///
    /// - Parameter node: The leaf.
    func meetArray(at node: Int32) {
        guard arrays[node] == nil else { return }
        arrays[node] = []
    }

    /// Note a value the record writes otherwise than the event encodes it, before the walk goes down into it.
    ///
    /// - Parameters:
    ///   - value: A value the walk met.
    ///   - node: Its node.
    /// - Returns: Is the value a leaf the record writes as a string, which needs no walk into it?
    func derive(_ value: some Encodable, at node: Int32) -> Bool {
        guard trie.derives(node) else { return false }
        switch value {
        case let time as TimeSpec where trie.isLeaf(node):
            note(IndicatorValue(time.humanFormat()), at: node)
            return true
        case let time as TimeVal where trie.isLeaf(node):
            note(IndicatorValue(time.humanFormat()), at: node)
            return true
        case let file as File:
            keep(MessageValues.name(ofPath: file.path), at: trie.child(of: node, "name"))
        case let process as Process:
            let flags = process.codesigning_flags
            keep(IndicatorValue(process.cdhash?.uppercased()), at: trie.child(of: node, "cdhash"))
            keep(ProcessHelpers.codeSigningFlagNames(flags), size: ProcessHelpers.codeSigningFlagCount(flags),
                 at: trie.child(of: node, "codesigning_flag_names"))
        case let mmap as MMapEvent:
            keep(.protection, of: mmap.protection, at: trie.child(of: node, "protection_names"))
            keep(.protection, of: mmap.max_protection, at: trie.child(of: node, "max_protection_names"))
            keep(.flags, of: mmap.flags, at: trie.child(of: node, "flag_names"))
        case let setmode as SetModeEvent:
            let mode = FileMode(setmode.mode), previous = FileMode(statMode: setmode.target.stat.st_mode)
            keep(IndicatorValue(mode.symbolic), at: trie.child(of: node, "mode_symbolic"))
            keep(IndicatorValue(previous.map { Int($0.permissions) }), at: trie.child(of: node, "previous_mode"))
            keep(FileModeCallout.added(to: mode, from: previous).map(\.telemetryName),
                 size: FileModeCallout.addedCount(to: mode, from: previous), at: trie.child(of: node, "mode_added"))
        case let login as LoginLoginEvent:
            keep(IndicatorValue(login.succcess), at: trie.child(of: node, "success"))
        default:
            break
        }
        return false
    }

    /// Go down into a value met at a node, unless the record writes it otherwise (``derive(_:at:)``). An array whose
    /// size a field reads is counted here, from its own `count`. It's gone down into only when its strings are read
    /// too. An array the record works out was counted where its parent was met.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - node: Its node, or -1 for none.
    /// - Throws: What encoding the value throws.
    func descend(_ value: some Encodable, at node: Int32) throws {
        guard node >= 0, !derive(value, at: node) else { return }
        if trie.counts(node), let array = value as? any Collection {
            if !trie.isWorkedOut(node) {
                note(.number(Double(array.count), isInteger: true), at: trie.counted(node, size: array.count))
            }
            guard trie.isLeaf(node) else { return }
        }
        try value.encode(to: RecordWalkEncoder(walk: self, node: node))
    }

    /// - Parameters:
    ///   - value: A value worked out as the record writes it.
    ///   - node: A leaf to keep it at, or else nothing.
    private func keep(_ value: @autoclosure () -> IndicatorValue, at node: Int32) {
        guard trie.isLeaf(node) else { return }
        found.append((node, value()))
        derived.insert(node)
    }

    /// Keep an array worked out as the record writes it at its leaf, and its size where a field counts it. Only a
    /// leaf makes the array. A count alone takes its size from `size`, which makes nothing.
    ///
    /// - Parameters:
    ///   - strings: The array, as the record writes it.
    ///   - size: Its size, worked out without making it.
    ///   - node: The array's node, or -1.
    private func keep(_ strings: @autoclosure () -> [String], size: @autoclosure () -> Int, at node: Int32) {
        var made: Int?
        if trie.isLeaf(node) {
            let strings = strings()
            keep(.strings(strings), at: node)
            made = strings.count
        }
        guard trie.counts(node) else { return }
        let count = made ?? size()
        note(.number(Double(count), isInteger: true), at: trie.counted(node, size: count))
    }

    /// Keep an mmap's names of a value's bits, or their count (``keep(_:size:at:)``).
    ///
    /// - Parameters:
    ///   - table: The names.
    ///   - value: The value.
    ///   - node: The names' node, or -1.
    private func keep(_ table: MemoryMappingNames, of value: Int32, at node: Int32) {
        keep(table.names(value), size: table.nameCount(value), at: node)
    }

    /// - Parameter double: A number encoded as one.
    /// - Returns: It, whole when it has no fraction, as a record's JSON reads back.
    static func number(_ double: Double) -> IndicatorValue {
        .number(double, isInteger: double.isFinite && double.rounded() == double && double.magnitude < 0x1p53)
    }
}

/// The encoder a walk hands each value it goes down into.
struct RecordWalkEncoder: Encoder {
    let walk: RecordWalk
    /// Where the value sits, or -1 when nothing's read under it.
    let node: Int32
    var codingPath: [CodingKey] { [] }
    var userInfo: [CodingUserInfoKey: Any] { [:] }

    func container<Key: CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
        KeyedEncodingContainer(RecordWalkKeyed<Key>(walk: walk, node: node))
    }

    func unkeyedContainer() -> UnkeyedEncodingContainer {
        RecordWalkUnkeyed(walk: walk, node: walk.trie.isLeaf(node) ? node : -1)
    }

    func singleValueContainer() -> SingleValueEncodingContainer {
        RecordWalkSingle(walk: walk, node: node)
    }
}

/// An object met on the walk: each key is looked up, and only those on a field's path are gone down.
private struct RecordWalkKeyed<Key: CodingKey>: KeyedEncodingContainerProtocol {
    let walk: RecordWalk
    let node: Int32
    var codingPath: [CodingKey] { [] }

    @inline(__always)
    private func leaf(_ key: Key) -> Int32? {
        let child = walk.trie.child(of: node, key.stringValue)
        return walk.trie.isLeaf(child) ? child : nil
    }

    mutating func encodeNil(forKey key: Key) throws {}
    mutating func encode(_ value: Bool, forKey key: Key) throws {
        if let leaf = leaf(key) { walk.note(IndicatorValue(value), at: leaf) }
    }
    mutating func encode(_ value: String, forKey key: Key) throws {
        if let leaf = leaf(key) { walk.note(IndicatorValue(value), at: leaf) }
    }
    mutating func encode(_ value: Double, forKey key: Key) throws {
        if let leaf = leaf(key) { walk.note(RecordWalk.number(value), at: leaf) }
    }
    mutating func encode(_ value: Float, forKey key: Key) throws {
        if let leaf = leaf(key) { walk.note(RecordWalk.number(Double(value)), at: leaf) }
    }
    mutating func encode(_ value: Int, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: Int8, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: Int16, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: Int32, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: Int64, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: UInt, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: UInt8, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: UInt16, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: UInt32, forKey key: Key) throws { integer(value, key) }
    mutating func encode(_ value: UInt64, forKey key: Key) throws { integer(value, key) }

    @inline(__always)
    private func integer(_ value: some BinaryInteger, _ key: Key) {
        if let leaf = leaf(key) { walk.note(.number(Double(value), isInteger: true), at: leaf) }
    }

    mutating func encode<T: Encodable>(_ value: T, forKey key: Key) throws {
        try walk.descend(value, at: walk.trie.child(of: node, key.stringValue))
    }

    mutating func nestedContainer<NestedKey: CodingKey>(keyedBy keyType: NestedKey.Type,
                                                        forKey key: Key) -> KeyedEncodingContainer<NestedKey> {
        KeyedEncodingContainer(RecordWalkKeyed<NestedKey>(walk: walk, node: walk.trie.child(of: node, key.stringValue)))
    }

    mutating func nestedUnkeyedContainer(forKey key: Key) -> UnkeyedEncodingContainer {
        let child = walk.trie.child(of: node, key.stringValue)
        return RecordWalkUnkeyed(walk: walk, node: walk.trie.isLeaf(child) ? child : -1)
    }

    mutating func superEncoder() -> Encoder { RecordWalkEncoder(walk: walk, node: -1) }
    mutating func superEncoder(forKey key: Key) -> Encoder { RecordWalkEncoder(walk: walk, node: -1) }
}

/// An array met on the walk: a field's array of strings, kept whole, or else nothing.
private struct RecordWalkUnkeyed: UnkeyedEncodingContainer {
    let walk: RecordWalk
    let node: Int32
    var codingPath: [CodingKey] { [] }
    private(set) var count = 0

    /// - Parameters:
    ///   - walk: The walk.
    ///   - node: The field's node, or -1 to keep nothing.
    init(walk: RecordWalk, node: Int32) {
        /// An array worked out as the record writes it is kept, not the event's own.
        let node = walk.derived.contains(node) ? -1 : node
        (self.walk, self.node) = (walk, node)
        if node >= 0 { walk.meetArray(at: node) }
    }

    mutating func encodeNil() throws { count += 1 }
    mutating func encode(_ value: String) throws {
        count += 1
        if node >= 0 { walk.arrays[node, default: []].append(value) }
    }
    mutating func encode<T: Encodable>(_ value: T) throws {
        count += 1
        guard node >= 0 else { return }
        var strings = StringCollector()
        try value.encode(to: strings.encoder)
        if let string = strings.value { walk.arrays[node, default: []].append(string) }
    }
    mutating func encode(_ value: Bool) throws { count += 1 }
    mutating func encode(_ value: Double) throws { count += 1 }
    mutating func encode(_ value: Float) throws { count += 1 }
    mutating func encode(_ value: Int) throws { count += 1 }
    mutating func encode(_ value: Int8) throws { count += 1 }
    mutating func encode(_ value: Int16) throws { count += 1 }
    mutating func encode(_ value: Int32) throws { count += 1 }
    mutating func encode(_ value: Int64) throws { count += 1 }
    mutating func encode(_ value: UInt) throws { count += 1 }
    mutating func encode(_ value: UInt8) throws { count += 1 }
    mutating func encode(_ value: UInt16) throws { count += 1 }
    mutating func encode(_ value: UInt32) throws { count += 1 }
    mutating func encode(_ value: UInt64) throws { count += 1 }

    mutating func nestedContainer<NestedKey: CodingKey>(keyedBy keyType: NestedKey.Type)
        -> KeyedEncodingContainer<NestedKey> {
        count += 1
        return KeyedEncodingContainer(RecordWalkKeyed<NestedKey>(walk: walk, node: -1))
    }

    mutating func nestedUnkeyedContainer() -> UnkeyedEncodingContainer {
        count += 1
        return RecordWalkUnkeyed(walk: walk, node: -1)
    }

    mutating func superEncoder() -> Encoder { RecordWalkEncoder(walk: walk, node: -1) }
}

/// A single value met on the walk: a leaf's scalar, encoded through its own type, as a raw value or a `UUID` is.
private struct RecordWalkSingle: SingleValueEncodingContainer {
    let walk: RecordWalk
    let node: Int32
    var codingPath: [CodingKey] { [] }

    mutating func encodeNil() throws {}
    mutating func encode(_ value: Bool) throws { walk.note(IndicatorValue(value), at: node) }
    mutating func encode(_ value: String) throws { walk.note(IndicatorValue(value), at: node) }
    mutating func encode(_ value: Double) throws { walk.note(RecordWalk.number(value), at: node) }
    mutating func encode(_ value: Float) throws { walk.note(RecordWalk.number(Double(value)), at: node) }
    mutating func encode(_ value: Int) throws { integer(value) }
    mutating func encode(_ value: Int8) throws { integer(value) }
    mutating func encode(_ value: Int16) throws { integer(value) }
    mutating func encode(_ value: Int32) throws { integer(value) }
    mutating func encode(_ value: Int64) throws { integer(value) }
    mutating func encode(_ value: UInt) throws { integer(value) }
    mutating func encode(_ value: UInt8) throws { integer(value) }
    mutating func encode(_ value: UInt16) throws { integer(value) }
    mutating func encode(_ value: UInt32) throws { integer(value) }
    mutating func encode(_ value: UInt64) throws { integer(value) }

    @inline(__always)
    private func integer(_ value: some BinaryInteger) {
        walk.note(.number(Double(value), isInteger: true), at: node)
    }

    mutating func encode<T: Encodable>(_ value: T) throws {
        try walk.descend(value, at: node)
    }
}

/// Takes the one string an array's element encodes as, such as a raw value's.
private struct StringCollector {
    /// Where the string is kept.
    private final class Box { var value: String? }
    private let box = Box()

    /// The string, if the element was one.
    var value: String? { box.value }

    /// The encoder to give the element.
    var encoder: Encoder { Collector(box: box) }

    private struct Collector: Encoder, SingleValueEncodingContainer {
        let box: Box
        var codingPath: [CodingKey] { [] }
        var userInfo: [CodingUserInfoKey: Any] { [:] }
        func container<Key: CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
            KeyedEncodingContainer(RecordWalkKeyed<Key>(walk: RecordWalk(RecordPathTrie([])), node: -1))
        }
        func unkeyedContainer() -> UnkeyedEncodingContainer {
            RecordWalkUnkeyed(walk: RecordWalk(RecordPathTrie([])), node: -1)
        }
        func singleValueContainer() -> SingleValueEncodingContainer { self }
        mutating func encodeNil() throws {}
        mutating func encode(_ value: Bool) throws {}
        mutating func encode(_ value: String) throws { box.value = value }
        mutating func encode(_ value: Double) throws {}
        mutating func encode(_ value: Float) throws {}
        mutating func encode(_ value: Int) throws {}
        mutating func encode(_ value: Int8) throws {}
        mutating func encode(_ value: Int16) throws {}
        mutating func encode(_ value: Int32) throws {}
        mutating func encode(_ value: Int64) throws {}
        mutating func encode(_ value: UInt) throws {}
        mutating func encode(_ value: UInt8) throws {}
        mutating func encode(_ value: UInt16) throws {}
        mutating func encode(_ value: UInt32) throws {}
        mutating func encode(_ value: UInt64) throws {}
        mutating func encode<T: Encodable>(_ value: T) throws { try value.encode(to: self) }
    }
}
