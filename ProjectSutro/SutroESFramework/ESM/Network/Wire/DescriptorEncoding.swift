//
//  DescriptorEncoding.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import ObjectiveC


// MARK: - Descriptor encodings
/// The descriptor layouts the running NetworkStatistics framework was built with, for a macOS whose descriptors no
/// known layout fits. The framework's source classes keep a descriptor in an instance variable whose type encoding
/// names every field (`{nstat_tcp_descriptor="upid"Q"eupid"Q...}`). The encoding is read with the Objective-C runtime
/// and laid out as C does, with natural alignment and bit-fields packed into 4-byte units.
enum DescriptorEncoding {
    /// The private framework, loaded only when no known layout fits.
    private static let framework = "/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics"
    /// The class that keeps each kind's descriptor, in its `_descriptor` instance variable.
    private static let classes: [DescriptorLayout.Kind: String] = [.tcp: "NWStatisticsTCPSource",
                                                                   .udp: "NWStatisticsUDPSource"]
    /// The fields the client reads, with how many bytes it reads of each. Each must be at least that wide.
    private static let read: [(name: String, width: Int)] = [
        ("upid", 8), ("eupid", 8), ("start_timestamp", 8), ("timestamp", 8), ("pid", 4), ("epid", 4), ("local", 28),
        ("remote", 28), ("pname", 64), ("ifnet_properties", 4)
    ]
    /// The framework's layouts, read the first time one is asked for.
    private static let layouts: [DescriptorLayout.Kind: DescriptorLayout] = {
        guard dlopen(framework, RTLD_LAZY | RTLD_LOCAL) != nil else { return [:] }
        return classes.reduce(into: [:]) { layouts, entry in
            guard let type = NSClassFromString(entry.value), let ivar = class_getInstanceVariable(type, "_descriptor"),
                  let encoding = ivar_getTypeEncoding(ivar) else { return }
            layouts[entry.key] = layout(entry.key, encoding: String(cString: encoding))
        }
    }()

    /// The running framework's layout of a kind.
    ///
    /// - Parameter kind: The kind.
    /// - Returns: The layout, or `nil` when the framework or its encoding can't be read.
    static func layout(of kind: DescriptorLayout.Kind) -> DescriptorLayout? {
        layouts[kind]
    }

    /// A layout from a descriptor's named type encoding.
    ///
    /// - Parameters:
    ///   - kind: The kind of descriptor.
    ///   - encoding: Its encoding.
    /// - Returns: The layout, or `nil` when the encoding doesn't parse, or lacks a field the client reads or has one
    ///   narrower than what's read of it.
    static func layout(_ kind: DescriptorLayout.Kind, encoding: String) -> DescriptorLayout? {
        guard let parsed = fields(of: encoding) else { return nil }
        /// A field's offset, when it's at least as wide as what's read of it. Every field lies within the struct.
        ///
        /// - Parameters:
        ///   - name: The field's name.
        ///   - width: The bytes read of it.
        /// - Returns: Its offset, or `nil` when it's missing or narrower.
        func offset(_ name: String, _ width: Int) -> Int? {
            parsed.fields[name].flatMap { $0.size >= width ? $0.offset : nil }
        }
        let offsets = Self.read.compactMap { offset($0.name, $0.width) }
        let state = offset("state", 4)
        guard offsets.count == Self.read.count, kind == .udp || state != nil else { return nil }
        return DescriptorLayout(kind: kind, size: parsed.size, upid: offsets[0], eupid: offsets[1], start: offsets[2],
                                timestamp: offsets[3], pid: offsets[4], epid: offsets[5], local: offsets[6],
                                remote: offsets[7], pname: offsets[8], ifnetProperties: offsets[9],
                                state: kind == .tcp ? state : nil)
    }

    /// A struct's size and its named top-level fields, from its type encoding.
    ///
    /// - Parameter encoding: The encoding, with field names.
    /// - Returns: The size, and each field's offset and size by name, or `nil` when it doesn't parse.
    static func fields(of encoding: String) -> (size: Int, fields: [String: (offset: Int, size: Int)])? {
        var parser = EncodingParser(bytes: Array(encoding.utf8))
        guard let type = parser.type(), parser.index == parser.bytes.count else { return nil }
        let fields = Dictionary(type.fields.map { ($0.name, ($0.offset, $0.size)) }) { first, _ in first }
        return (type.size, fields)
    }
}


// MARK: - The encoding parser
/// Reads one Objective-C type encoding.
private struct EncodingParser {
    /// One type's size and alignment, a bit-field's width, and a struct's or union's fields.
    struct Layout {
        var size = 0, alignment = 1, bits = 0
        var fields: [(name: String, offset: Int, size: Int)] = []
    }

    let bytes: [UInt8]
    var index = 0

    /// Each primitive's size, which is its alignment.
    private static let primitives: [UInt8: Int] = Dictionary(uniqueKeysWithValues: [
        ("cCB", 1), ("sS", 2), ("iIlLf", 4), ("qQd*@#:?", 8)
    ].flatMap { codes, size in codes.utf8.map { ($0, size) } })

    /// Read the type at the parser's place.
    ///
    /// - Returns: Its layout, or `nil` when it doesn't parse.
    mutating func type() -> Layout? {
        while index < bytes.count, "rnNoORV".utf8.contains(bytes[index]) { index += 1 }
        guard index < bytes.count else { return nil }
        let code = bytes[index]
        index += 1
        switch code {
        case UInt8(ascii: "^"):
            guard take("v") || type() != nil else { return nil }
            return Layout(size: 8, alignment: 8)
        case UInt8(ascii: "b"):
            return Layout(bits: number())
        case UInt8(ascii: "["):
            let count = number()
            guard let element = type(), take("]") else { return nil }
            return Layout(size: count * element.size, alignment: element.alignment)
        case UInt8(ascii: "{"), UInt8(ascii: "("):
            return aggregate(isUnion: code == UInt8(ascii: "("))
        default:
            return Self.primitives[code].map { Layout(size: $0, alignment: $0) }
        }
    }

    /// Read a struct or union after its opening brace. Its name comes first, then `=`, then each quoted field.
    ///
    /// - Parameter isUnion: Is it a union, whose fields all start at 0?
    /// - Returns: Its layout, or `nil` when it doesn't parse.
    private mutating func aggregate(isUnion: Bool) -> Layout? {
        let close = UInt8(ascii: isUnion ? ")" : "}")
        while index < bytes.count, bytes[index] != UInt8(ascii: "="), bytes[index] != close { index += 1 }
        var layout = Layout(), offset = 0, bits = 0
        /// Bit-fields in a row share 4-byte units.
        func endBits() {
            if bits > 0 { offset = Self.align(offset, 4) + 4 * ((bits + 31) / 32) }
            bits = 0
        }
        if take("=") {
            while index < bytes.count, bytes[index] != close {
                var name = ""
                if take("\"") {
                    let end = bytes[index...].firstIndex(of: UInt8(ascii: "\"")) ?? bytes.count
                    name = String(decoding: bytes[index..<end], as: UTF8.self)
                    index = end + 1
                }
                guard let field = type() else { return nil }
                if field.bits > 0 {
                    bits += field.bits
                    layout.alignment = max(layout.alignment, 4)
                    continue
                }
                endBits()
                layout.alignment = max(layout.alignment, field.alignment)
                let start = isUnion ? 0 : Self.align(offset, field.alignment)
                layout.fields.append((name, start, field.size))
                offset = isUnion ? max(offset, field.size) : start + field.size
            }
        }
        guard take(close) else { return nil }
        endBits()
        layout.size = Self.align(offset, layout.alignment)
        return layout
    }

    /// Read a decimal number.
    ///
    /// - Returns: The number, 0 when there's none.
    private mutating func number() -> Int {
        var value = 0
        while index < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[index]), value < 1 << 20 {
            value = value * 10 + Int(bytes[index] - UInt8(ascii: "0"))
            index += 1
        }
        return value
    }

    /// Step over one expected character.
    ///
    /// - Parameter character: The character.
    /// - Returns: Whether it was there.
    private mutating func take(_ character: Unicode.Scalar) -> Bool {
        take(UInt8(ascii: character))
    }

    /// Step over one expected byte.
    ///
    /// - Parameter byte: The byte.
    /// - Returns: Whether it was there.
    private mutating func take(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    /// - Parameters:
    ///   - offset: An offset.
    ///   - alignment: An alignment.
    /// - Returns: The offset rounded up to the alignment.
    private static func align(_ offset: Int, _ alignment: Int) -> Int {
        (offset + alignment - 1) / alignment * alignment
    }
}
