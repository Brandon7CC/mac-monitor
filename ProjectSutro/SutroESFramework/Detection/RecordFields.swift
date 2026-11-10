//
//  RecordFields.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Record fields
/// The record fields this process has given numbers (``IndicatorField``): each key path a rule named that isn't a
/// direct field, with its kind, numbered after the direct fields in the order rules first named them. A number is never
/// taken back, so a compiled program's fields keep naming the same paths. The telemetry schema bounds how many there
/// can be.
///
/// **Threading:** thread-safe. Only compiling a rule and describing a field take its lock; reading an event's values
/// never does.
final class RecordFields: @unchecked Sendable {
    /// The one table, for every set in the process.
    static let shared = RecordFields()

    /// Guards the table.
    private let lock = NSLock()
    /// Each record field's key path and kind, by its number less the direct fields'.
    private var descriptors: [(path: String, kind: IndicatorField.Kind)] = []
    /// Each record field by its key path.
    private var byPath: [String: IndicatorField] = [:]

    /// - Parameters:
    ///   - path: A key path of the record that isn't a direct field's.
    ///   - kind: What its value is.
    /// - Returns: Its field, numbered the first time it's asked for.
    func field(_ path: String, kind: IndicatorField.Kind) -> IndicatorField {
        lock.withLock {
            if let field = byPath[path] { return field }
            let field = IndicatorField(rawValue: UInt16(IndicatorField.allCases.count + descriptors.count))
            descriptors.append((path, kind))
            byPath[path] = field
            return field
        }
    }

    /// - Parameter field: A record field.
    /// - Returns: Its key path and kind.
    func descriptor(of field: IndicatorField) -> (path: String, kind: IndicatorField.Kind) {
        lock.withLock { descriptors[Int(field.rawValue) - IndicatorField.allCases.count] }
    }
}


// MARK: - The schema's key paths
/// Every key path of the telemetry schema this build bundles (``TelemetrySchema``), with what its value is: the key
/// paths a rule can compare, and why the others can't be.
enum RecordSchema {
    /// What a key path is.
    enum Lookup: Equatable {
        /// A value a rule compares.
        case kind(IndicatorField.Kind)
        /// A key path of the record whose value a rule can't compare on its own, and why.
        case unsupported(String)
        /// Not a key path of the record.
        case absent
    }

    /// Every key path the schema has, read from the bundled schema once.
    static let paths: [String: Lookup] = {
        guard let data = try? TelemetrySchema.data(),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [:] }
        var reader = Reader(definitions: root["$defs"] as? [String: Any] ?? [:])
        reader.walk(root, path: [], inArray: false, through: [])
        return reader.paths
    }()

    /// - Parameter path: A key path, as in `event.exec.args`.
    /// - Returns: What it is.
    static func lookup(_ path: String) -> Lookup {
        guard let lookup = paths[path] else { return .absent }
        let stored = storedOnly.contains { path == $0 || path.hasPrefix($0 + ".") || path.hasPrefix($0 + "_") }
        if case .kind = lookup, stored {
            return .unsupported("Mac Monitor writes it as it stores the event, "
                                + "after the Security Extension evaluates it")
        }
        return lookup
    }

    /// The key paths the record has and the Security Extension's event doesn't, or has otherwise: what Mac Monitor
    /// writes as it stores or exports an event (`RecordFieldParityTests`).
    static let storedOnly = ["seq_num", "global_seq_num", "telemetry_version", "event.gatekeeper_user_override.file",
                             "event.gatekeeper_user_override.sha256"]

    /// Walks the schema, from the root through each object's properties and each array's items.
    private struct Reader {
        /// The schema's definitions, by name.
        let definitions: [String: Any]
        /// The key paths found.
        var paths: [String: Lookup] = [:]

        /// - Parameters:
        ///   - node: A schema, or a part of one.
        ///   - path: Its key path's components.
        ///   - inArray: Is it inside an array of objects?
        ///   - through: The definitions on the way to it, so one that holds itself isn't walked forever.
        mutating func walk(_ node: [String: Any], path: [String], inArray: Bool, through: [String]) {
            var node = node, through = through
            if let reference = node["$ref"] as? String {
                let name = String(reference.split(separator: "/").last ?? "")
                guard !through.contains(name), let definition = definitions[name] as? [String: Any] else { return }
                node = definition
                through.append(name)
            }
            var scalars = Set<String>(), isObject = false
            let alternatives = (node["anyOf"] as? [[String: Any]] ?? []) + (node["oneOf"] as? [[String: Any]] ?? [])
                + (node["allOf"] as? [[String: Any]] ?? [])
            for alternative in alternatives {
                var resolved = alternative, inner = through
                if let reference = alternative["$ref"] as? String {
                    let name = String(reference.split(separator: "/").last ?? "")
                    guard !inner.contains(name), let definition = definitions[name] as? [String: Any] else { continue }
                    resolved = definition
                    inner.append(name)
                }
                if resolved["properties"] != nil || resolved["type"] as? String == "array" {
                    isObject = isObject || resolved["properties"] != nil
                    walk(resolved, path: path, inArray: inArray, through: inner)
                } else {
                    scalars.formUnion(Self.types(of: resolved))
                }
            }
            if let properties = node["properties"] as? [String: Any] {
                isObject = true
                for (key, value) in properties {
                    if let child = value as? [String: Any] {
                        walk(child, path: path + [key], inArray: inArray, through: through)
                    }
                }
            }
            let types = Self.types(of: node)
            if types.contains("array"), let items = node["items"] as? [String: Any] {
                if Self.isString(items, definitions) {
                    note(path, inArray ? .unsupported("it's inside an array of objects") : .kind(.strings))
                } else {
                    walk(items, path: path, inArray: true, through: through)
                    note(path, .unsupported("it's an array of other than strings"))
                }
                return
            }
            scalars.formUnion(types.subtracting(["object"]))
            guard !path.isEmpty else { return }
            if isObject {
                note(path, .unsupported("it's an object"))
            } else if !scalars.isEmpty {
                note(path, inArray ? .unsupported("it's inside an array of objects") : Self.lookup(of: scalars))
            }
        }

        /// Keep what a key path is, unless a value it can be compared as is known already.
        ///
        /// - Parameters:
        ///   - path: The key path's components.
        ///   - lookup: What it is.
        private mutating func note(_ path: [String], _ lookup: Lookup) {
            let key = path.joined(separator: ".")
            if case .kind = paths[key] { return }
            paths[key] = lookup
        }

        /// - Parameter scalars: The JSON types a value can have.
        /// - Returns: What a rule compares it as.
        private static func lookup(of scalars: Set<String>) -> Lookup {
            switch scalars.subtracting(["null"]) {
            case ["string"]: .kind(.string)
            case ["integer"], ["number"], ["integer", "number"]: .kind(.number)
            case ["boolean"]: .kind(.boolean)
            case []: .unsupported("it's always null")
            default: .unsupported("its value can be of different kinds")
            }
        }

        /// - Parameter node: A schema.
        /// - Returns: The JSON types its `type`, `enum` or `const` names.
        private static func types(of node: [String: Any]) -> Set<String> {
            var types = Set<String>()
            if let type = node["type"] as? String { types.insert(type) }
            if let list = node["type"] as? [String] { types.formUnion(list) }
            for value in (node["enum"] as? [Any] ?? []) + [node["const"]].compactMap({ $0 }) {
                switch value {
                case is String: types.insert("string")
                case is NSNull: types.insert("null")
                case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID(): types.insert("boolean")
                case is NSNumber: types.insert("number")
                default: break
                }
            }
            return types
        }

        /// - Parameters:
        ///   - node: An array's items.
        ///   - definitions: The schema's definitions.
        /// - Returns: Are they strings?
        private static func isString(_ node: [String: Any], _ definitions: [String: Any]) -> Bool {
            var node = node
            if let reference = node["$ref"] as? String,
               let definition = definitions[String(reference.split(separator: "/").last ?? "")] as? [String: Any] {
                node = definition
            }
            return types(of: node).subtracting(["null"]) == ["string"]
        }
    }
}


// MARK: - Reading record fields
/// The record fields a compiled set reads, by their key paths' components, and how to read them all from an event in
/// one walk of its own encoding: the `Message` a capture lane builds, encoded as it's sent, which is the record but for
/// its event's payload under `_0`, which the walk passes through.
///
/// The walk goes down only the keys a field's path names: every other value is skipped where its key is met, without
/// encoding it, so an event costs a lookup per key on the way, not an encode. A value read is the record's
/// (`RecordFieldParityTests`), where the record writes a value the event encodes otherwise or not at all: a `timespec`
/// or `timeval` as its UTC time, a file's `name` from its path, a code directory hash in capitals, a process's code
/// signing flags' names, an mmap's protections' and flags' names, a setmode's mode as the record describes it, and a
/// login's `success`, which the event spells `succcess`.
///
/// **Threading:** immutable once made.
final class RecordPathTrie: @unchecked Sendable {
    /// A key path component, and the fields under it.
    struct Node {
        /// The next components' names, and their nodes in the same order. Most nodes have a few, which a scan
        /// compares faster than a hash.
        var keys: [String] = [], next: [Int32] = []
        /// The next components by name, once there are more than ``RecordPathTrie/scanned``.
        var index: [String: Int32]?
        /// The field whose path ends here.
        var field: IndicatorField?
        /// Is a value met here one the record writes otherwise (``RecordWalk/derive(_:at:)``): a leaf, which may be a
        /// time, or a node with a child the record works out, such as a file's `name`?
        var derives = false

        /// - Parameter key: A component.
        /// - Returns: Its node, or `nil` when no field's path goes on through it.
        @inline(__always)
        func child(_ key: String) -> Int32? {
            if let index { return index[key] }
            for position in keys.indices where keys[position] == key { return next[position] }
            return nil
        }
    }

    /// The most children a node scans for a component, past which it looks them up by hash.
    static let scanned = 6
    /// The components the record works out from their parent's value (``RecordWalk/derive(_:at:)``).
    static let derivedKeys: Set<String> = ["name", "cdhash", "codesigning_flag_names", "protection_names",
                                            "max_protection_names", "flag_names", "mode_symbolic", "previous_mode",
                                            "mode_added", "success"]

    /// The nodes, the root first.
    private(set) var nodes = [Node()]
    /// The fields, each once.
    let fields: [IndicatorField]

    /// - Parameter fields: Fields, record fields among them. Direct fields are left out.
    init(_ fields: some Sequence<IndicatorField>) {
        var seen = Set<IndicatorField>(), unique: [IndicatorField] = []
        for field in fields where !field.isDirect && seen.insert(field).inserted { unique.append(field) }
        self.fields = unique
        for field in unique {
            var node = 0
            for component in field.path.split(separator: ".").map(String.init) {
                if let child = nodes[node].child(component) {
                    node = Int(child)
                    continue
                }
                nodes.append(Node())
                let child = Int32(nodes.count - 1)
                nodes[node].keys.append(component)
                nodes[node].next.append(child)
                if Self.derivedKeys.contains(component) { nodes[node].derives = true }
                if nodes[node].keys.count > Self.scanned {
                    nodes[node].index = Dictionary(uniqueKeysWithValues: zip(nodes[node].keys, nodes[node].next))
                }
                node = Int(child)
            }
            nodes[node].field = field
            nodes[node].derives = true
        }
    }

    /// Does it read nothing?
    var isEmpty: Bool { fields.isEmpty }

    /// Read every field's value from an event, as its record has it. A field the event doesn't have is
    /// ``IndicatorValue/null``.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - found: Takes each field and its value.
    func read(_ message: borrowing Message, _ found: (IndicatorField, IndicatorValue) -> Void) {
        let walk = RecordWalk(self)
        try? message.encode(to: RecordWalkEncoder(walk: walk, node: 0))
        for (node, value) in walk.found {
            if let field = nodes[Int(node)].field { found(field, value) }
        }
        for (node, strings) in walk.arrays {
            if let field = nodes[Int(node)].field { found(field, .strings(strings)) }
        }
    }

    /// - Parameters:
    ///   - node: A node, or -1 for none.
    ///   - key: A key met under it.
    /// - Returns: The node for the key, the same one for `_0`, which the walk passes through, or -1 for none.
    @inline(__always)
    func child(of node: Int32, _ key: String) -> Int32 {
        guard node >= 0 else { return -1 }
        if key == "_0" { return node }
        return nodes[Int(node)].child(key) ?? -1
    }

    /// - Parameter node: A node, or -1.
    /// - Returns: Might a value met there be one the record writes otherwise?
    @inline(__always)
    func derives(_ node: Int32) -> Bool {
        node >= 0 && nodes[Int(node)].derives
    }

    /// - Parameter node: A node, or -1.
    /// - Returns: Does a field's path end there?
    @inline(__always)
    func isLeaf(_ node: Int32) -> Bool {
        node >= 0 && nodes[Int(node)].field != nil
    }
}

/// What one walk found.
private final class RecordWalk {
    let trie: RecordPathTrie
    /// The scalars found, by node.
    var found: [(Int32, IndicatorValue)] = []
    /// The arrays of strings found, by node.
    var arrays: [Int32: [String]] = [:]
    /// The nodes whose values were worked out as the record writes them, which the encoding's own don't replace.
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
            keep(IndicatorValue(process.cdhash?.uppercased()), at: trie.child(of: node, "cdhash"))
            keep(.strings(ProcessHelpers.codeSigningFlagNames(process.codesigning_flags)),
                 at: trie.child(of: node, "codesigning_flag_names"))
        case let mmap as MMapEvent:
            keep(.strings(MemoryMappingNames.protection.names(mmap.protection)),
                 at: trie.child(of: node, "protection_names"))
            keep(.strings(MemoryMappingNames.protection.names(mmap.max_protection)),
                 at: trie.child(of: node, "max_protection_names"))
            keep(.strings(MemoryMappingNames.flags.names(mmap.flags)), at: trie.child(of: node, "flag_names"))
        case let setmode as SetModeEvent:
            let mode = FileMode(setmode.mode), previous = FileMode(statMode: setmode.target.stat.st_mode)
            keep(IndicatorValue(mode.symbolic), at: trie.child(of: node, "mode_symbolic"))
            keep(IndicatorValue(previous.map { Int($0.permissions) }), at: trie.child(of: node, "previous_mode"))
            keep(.strings(FileModeCallout.added(to: mode, from: previous).map(\.telemetryName)),
                 at: trie.child(of: node, "mode_added"))
        case let login as LoginLoginEvent:
            keep(IndicatorValue(login.succcess), at: trie.child(of: node, "success"))
        default:
            break
        }
        return false
    }

    /// - Parameters:
    ///   - value: A value worked out as the record writes it.
    ///   - node: A leaf to keep it at, or else nothing.
    private func keep(_ value: @autoclosure () -> IndicatorValue, at node: Int32) {
        guard trie.isLeaf(node) else { return }
        found.append((node, value()))
        derived.insert(node)
    }

    /// - Parameter double: A number encoded as one.
    /// - Returns: It, whole when it has no fraction, as a record's JSON reads back.
    static func number(_ double: Double) -> IndicatorValue {
        .number(double, isInteger: double.isFinite && double.rounded() == double && double.magnitude < 0x1p53)
    }
}

/// The encoder a walk hands each value it goes down into.
private struct RecordWalkEncoder: Encoder {
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
        let child = walk.trie.child(of: node, key.stringValue)
        guard child >= 0, !walk.derive(value, at: child) else { return }
        try value.encode(to: RecordWalkEncoder(walk: walk, node: child))
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
        guard !walk.derive(value, at: node) else { return }
        try value.encode(to: RecordWalkEncoder(walk: walk, node: node))
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
