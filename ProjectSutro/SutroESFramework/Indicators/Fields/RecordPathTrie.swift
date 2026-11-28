//
//  RecordPathTrie.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


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
/// A count is the size of the array the walk meets. The walk doesn't go into a counted array unless its strings are
/// read. A missing array, or a missing parent, counts as `nil`, as `NSPredicate` reads it on the record. An exec's
/// empty certificate chain counts as `nil` too, as its record leaves it out (``emptyLeftOut``). An array the record
/// works out, such as a process's code signing flags' names, is counted from the value it's worked out from. Its
/// strings aren't made.
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
        /// The node of the field that counts the array met here (`.@count`), or -1 for none.
        var counted: Int32 = -1
        /// Is its key one the record works out from its parent's value (``RecordPathTrie/derivedKeys``)? An array
        /// met here is counted where its parent is met (``RecordWalk/derive(_:at:)``).
        var isWorkedOut = false
        /// Does the record leave the array met here out when it's empty (``RecordPathTrie/emptyLeftOut``)?
        var leavesOutEmpty = false

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
    /// The arrays the record leaves out when they're empty, which the event encodes empty. An empty one counts as
    /// `nil` (`RecordFieldParityTests`).
    static let emptyLeftOut: Set<String> = ["event.exec.certificate_chain"]

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
                if Self.derivedKeys.contains(component) {
                    nodes[node].derives = true
                    nodes[Int(child)].isWorkedOut = true
                }
                if component == RecordSchema.count {
                    nodes[node].counted = child
                    let array = String(field.path.dropLast(component.count + 1))
                    nodes[node].leavesOutEmpty = Self.emptyLeftOut.contains(array)
                }
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
    /// ``IndicatorValue/null``. A network flow's record is walked as it's written (``NetworkRecordView``), so the
    /// keys it doesn't have, such as `process.cdhash` or `version`, read as `nil` there too.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - found: Takes each field and its value.
    func read(_ message: borrowing Message, _ found: (IndicatorField, IndicatorValue) -> Void) {
        let walk = RecordWalk(self)
        let encoder = RecordWalkEncoder(walk: walk, node: 0)
        if message.event.isNetworkFlow {
            try? NetworkRecordView.encode(message, to: encoder)
        } else {
            try? message.encode(to: encoder)
        }
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

    /// - Parameter node: A node, or -1.
    /// - Returns: Does a field count the array met there?
    @inline(__always)
    func counts(_ node: Int32) -> Bool {
        node >= 0 && nodes[Int(node)].counted >= 0
    }

    /// - Parameter node: A node, or -1.
    /// - Returns: Is its value one the record works out from its parent's?
    @inline(__always)
    func isWorkedOut(_ node: Int32) -> Bool {
        node >= 0 && nodes[Int(node)].isWorkedOut
    }

    /// - Parameters:
    ///   - node: A node, or -1.
    ///   - size: The size of the array met there.
    /// - Returns: The leaf of the field that counts it, or -1 for none or for an empty one the record leaves out.
    @inline(__always)
    func counted(_ node: Int32, size: Int) -> Int32 {
        guard node >= 0, size > 0 || !nodes[Int(node)].leavesOutEmpty else { return -1 }
        return nodes[Int(node)].counted
    }
}
