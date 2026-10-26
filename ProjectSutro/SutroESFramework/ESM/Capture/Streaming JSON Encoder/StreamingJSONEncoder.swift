//
//  StreamingJSONEncoder.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Streaming JSON encoder
/// Encodes a value as `JSONEncoder` does with its default options, writing the JSON into one reused buffer while the
/// value's `encode(to:)` runs instead of building a tree of the whole value first.
///
/// `JSONEncoder` boxes every value into a tree (a hash table per object, an enum per scalar) and then writes the tree:
/// for a capture lane's ~4 KB event that was ~37 µs of the ~57 µs the lane spent on it. This encoder writes:
/// * every scalar's bytes as `JSONEncoder` writes them: strings escaped the same way (slashes included), numbers in
///   Swift's shortest form without a trailing `.0`, a `Date` as its seconds since 2001 (`deferredToDate`), `Data` in
///   base64, a `URL` as its absolute string, a `UUID` as its uppercase string, and `{}` for a nested value that encodes
///   nothing;
/// * an object's members in the order its `encode(to:)` encodes them (declaration order for a synthesized conformance),
///   where `JSONEncoder` writes them in its hash table's order, which changes from one encode to the next.
///
/// A value whose `encode(to:)` uses containers in a way that can't be streamed (going back to a container after
/// starting a later one at the same level, two values through one single-value container, `superEncoder()`) or encodes
/// nothing at all is encoded again by `JSONEncoder`, so the result is always what `JSONEncoder` would give.
///
/// Exports write their records as `JSONEncoder` does with `.sortedKeys` and `.withoutEscapingSlashes`
/// (``ProcessHelpers/eventToJSON(value:pretty:)``), which this does too when asked
/// (``init(sortsKeys:escapesSlashes:)``): each object's members are put in key order as the object closes, by the keys'
/// UTF-8 bytes, as `.sortedKeys` orders them. An object with a key twice, which `JSONEncoder` writes once, is left to
/// `JSONEncoder`. A ~3.6 KB event from the store took 34 µs this way, and 115 µs through `JSONEncoder`.
///
/// **Threading:** not thread-safe. Each capture lane owns one and uses it under its lock.
final class StreamingJSONEncoder {
    /// Everything an encode changes: the output (its bytes, how many are written, and how many fit) and the open
    /// containers.
    ///
    /// Behind a pointer rather than in stored properties, so that writing a byte or opening a container isn't a
    /// dynamic exclusivity check on the class's storage (`swift_beginAccess`, ~15% of an encode when the bytes were an
    /// `Array` property).
    struct State {
        var base: UnsafeMutablePointer<UInt8>
        var count: Int
        var capacity: Int
        /// The open objects and arrays, innermost last.
        var frames: [Frame] = []
        /// The last frame's ID.
        var lastFrameID = 0
        /// Set when the value uses containers in a way that can't be streamed: ``encode(_:)`` then asks
        /// `JSONEncoder`.
        var isUnstreamable = false
        /// Put each object's members in key order, as `.sortedKeys` does.
        let sortsKeys: Bool
        /// Escape `/` as `\/`, as `JSONEncoder` does without `.withoutEscapingSlashes`.
        let escapesSlashes: Bool
        /// The open objects' members so far, innermost object's last, while keys are sorted.
        var members: [Member] = []
        /// Where an object's members are copied while they're put in order.
        var scratch: UnsafeMutablePointer<UInt8>
        var scratchCapacity: Int
    }
    
    /// An object's member, while keys are sorted: its key, and where it starts (at its key, after any comma).
    struct Member {
        let key: String
        let start: Int
    }
    
    /// An open object or array.
    struct Frame {
        /// An object rather than an array.
        let isObject: Bool
        /// Tells this frame from any other opened at the same depth.
        let id: Int
        /// How many values it holds so far.
        var count = 0
        /// An object's first member in ``State/members``, while keys are sorted.
        var firstMember = 0
    }
    
    /// A container's frame, as its writer knows it: where it is, and which frame was there when it was opened.
    struct FrameReference {
        let index: Int
        let id: Int
        
        /// A container that can't write: anything written to it is dropped.
        static let invalid = FrameReference(index: .max, id: 0)
    }
    
    /// The buffer's size at first, and after an unusually large value.
    static let initialCapacity = 16_384
    /// A buffer that grew past this many bytes is given back after the encode.
    static let retainedCapacityLimit = 1 << 20
    
    /// The output and the open containers.
    let state: UnsafeMutablePointer<State>
    
    /// An encoder with an empty buffer.
    ///
    /// - Parameters:
    ///   - sortsKeys: Write each object's members in key order, as `JSONEncoder`'s `.sortedKeys` does.
    ///   - escapesSlashes: Escape `/`, as `JSONEncoder` does unless told `.withoutEscapingSlashes`.
    init(sortsKeys: Bool = false, escapesSlashes: Bool = true) {
        state = .allocate(capacity: 1)
        state.initialize(to: State(base: .allocate(capacity: Self.initialCapacity), count: 0,
                                   capacity: Self.initialCapacity, sortsKeys: sortsKeys, escapesSlashes: escapesSlashes,
                                   scratch: .allocate(capacity: sortsKeys ? Self.initialCapacity : 0),
                                   scratchCapacity: sortsKeys ? Self.initialCapacity : 0))
        state.pointee.frames.reserveCapacity(16)
        if sortsKeys { state.pointee.members.reserveCapacity(64) }
    }
    
    deinit {
        state.pointee.scratch.deallocate()
        state.pointee.base.deallocate()
        state.deinitialize(count: 1)
        state.deallocate()
    }
    
    /// Encode a value.
    ///
    /// - Parameter value: The value.
    /// - Returns: Its JSON, as `JSONEncoder` writes it but for the order of each object's members (unless they're
    ///   sorted, as `JSONEncoder` sorts them).
    /// - Throws: `EncodingError.invalidValue` for a number that isn't finite, as `JSONEncoder` throws, or the value's
    ///   own error.
    func encode<T: Encodable>(_ value: T) throws -> Data {
        state.pointee.count = 0
        state.pointee.frames.removeAll(keepingCapacity: true)
        state.pointee.members.removeAll(keepingCapacity: true)
        state.pointee.isUnstreamable = false
        defer { shrinkIfLarge() }
        try write(value, isTopLevel: true)
        guard !state.pointee.isUnstreamable else { return try fallback.encode(value) }
        return Data(bytes: state.pointee.base, count: state.pointee.count)
    }
    
    /// `JSONEncoder`, with the same options, for a value that can't be streamed.
    private var fallback: JSONEncoder {
        let encoder = JSONEncoder()
        if state.pointee.sortsKeys { encoder.outputFormatting.insert(.sortedKeys) }
        if !state.pointee.escapesSlashes { encoder.outputFormatting.insert(.withoutEscapingSlashes) }
        return encoder
    }
    
    /// Give back a buffer that grew for an unusually large value, such as an exec with a long environment.
    private func shrinkIfLarge() {
        guard state.pointee.capacity > Self.retainedCapacityLimit else { return }
        state.pointee.base.deallocate()
        state.pointee.base = .allocate(capacity: Self.initialCapacity)
        state.pointee.capacity = Self.initialCapacity
        state.pointee.count = 0
    }
    
    // MARK: Values
    /// Write a value: a scalar `JSONEncoder` writes itself directly, anything else through its `encode(to:)`.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - isTopLevel: The value being encoded rather than one inside it. A top-level value that writes nothing is
    ///     left to `JSONEncoder`, which throws for it. A nested one is written as `{}`, as `JSONEncoder` writes it.
    /// - Throws: When the value can't be encoded.
    func write<T: Encodable>(_ value: T, isTopLevel: Bool = false) throws {
        if T.self == String.self { return write(string: value as! String) }
        if T.self == UUID.self { return write(uuid: value as! UUID) }
        if T.self == Date.self { return try write(floating: (value as! Date).timeIntervalSinceReferenceDate) }
        if T.self == Data.self { return write(string: (value as! Data).base64EncodedString()) }
        if T.self == URL.self { return write(string: (value as! URL).absoluteString) }
        if T.self == Decimal.self { return write(raw: (value as! Decimal).description) }
        let depth = state.pointee.frames.count, start = state.pointee.count
        if !writeArtifact(value) { try value.encode(to: ValueWriter(encoder: self, depth: depth, start: start)) }
        close(downTo: depth)
        guard state.pointee.count == start else { return }
        if isTopLevel { state.pointee.isUnstreamable = true } else { write(raw: "{}" as StaticString) }
    }
    
    /// The container of the value whose frames start at a depth: the one it already opened there, or a new one if it
    /// has written nothing yet.
    ///
    /// - Parameters:
    ///   - depth: How many frames were open when the value started.
    ///   - start: Where in the buffer the value started.
    ///   - isObject: A keyed container rather than an unkeyed one.
    /// - Returns: The container's frame, or ``FrameReference/invalid`` if the value can't have one there.
    func container(at depth: Int, start: Int, isObject: Bool) -> FrameReference {
        if depth < state.pointee.frames.count, state.pointee.frames[depth].isObject == isObject {
            return FrameReference(index: depth, id: state.pointee.frames[depth].id)
        }
        guard depth == state.pointee.frames.count, state.pointee.count == start else {
            state.pointee.isUnstreamable = true
            return .invalid
        }
        return open(isObject: isObject)
    }
    
    /// May the value that started at a depth and buffer position write itself as a scalar now?
    ///
    /// - Parameters:
    ///   - depth: How many frames were open when the value started.
    ///   - start: Where in the buffer the value started.
    /// - Returns: `true` if it has written nothing yet. Otherwise `false`, and the value is left to `JSONEncoder`.
    func beginScalar(depth: Int, start: Int) -> Bool {
        guard depth == state.pointee.frames.count, state.pointee.count == start else {
            state.pointee.isUnstreamable = true
            return false
        }
        return true
    }
    
    // MARK: Containers
    /// Open an object or array.
    ///
    /// - Parameter isObject: An object rather than an array.
    /// - Returns: Its frame.
    func open(isObject: Bool) -> FrameReference {
        append(isObject ? UInt8(ascii: "{") : UInt8(ascii: "["))
        state.pointee.lastFrameID &+= 1
        state.pointee.frames.append(Frame(isObject: isObject, id: state.pointee.lastFrameID,
                                          firstMember: state.pointee.members.count))
        return FrameReference(index: state.pointee.frames.count - 1, id: state.pointee.lastFrameID)
    }
    
    /// Close the objects and arrays opened above a depth.
    ///
    /// - Parameter depth: How many frames stay open.
    func close(downTo depth: Int) {
        while state.pointee.frames.count > depth {
            let frame = state.pointee.frames.removeLast()
            if frame.isObject && state.pointee.sortsKeys { sortMembers(from: frame.firstMember) }
            append(frame.isObject ? UInt8(ascii: "}") : UInt8(ascii: "]"))
        }
    }
    
    /// Start a value in a container: close what a nested container left open, then write a comma after the
    /// container's previous value.
    ///
    /// - Parameter frame: The container's frame.
    /// - Returns: `false`, writing nothing, if the container was already closed.
    func element(in frame: FrameReference) -> Bool {
        guard frame.index < state.pointee.frames.count, state.pointee.frames[frame.index].id == frame.id else {
            state.pointee.isUnstreamable = true
            return false
        }
        close(downTo: frame.index + 1)
        if state.pointee.frames[frame.index].count > 0 { append(UInt8(ascii: ",")) }
        state.pointee.frames[frame.index].count += 1
        return true
    }
    
    /// Start an object's member: its key and a colon.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - frame: The object's frame.
    /// - Returns: `false`, writing nothing, if the object was already closed.
    func member(_ key: some CodingKey, in frame: FrameReference) -> Bool {
        guard element(in: frame) else { return false }
        let name = key.stringValue
        if state.pointee.sortsKeys { state.pointee.members.append(Member(key: name, start: state.pointee.count)) }
        write(string: name)
        append(UInt8(ascii: ":"))
        return true
    }
}
