//
//  StreamingJSONEncoder+Scalars.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Bytes
extension StreamingJSONEncoder {
    /// Make room for more bytes.
    ///
    /// - Parameter extra: How many bytes are about to be written.
    @inline(__always)
    func reserve(_ extra: Int) {
        let needed = state.pointee.count + extra
        guard needed > state.pointee.capacity else { return }
        let capacity = max(needed, state.pointee.capacity * 2)
        let base = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        base.update(from: state.pointee.base, count: state.pointee.count)
        state.pointee.base.deallocate()
        state.pointee.base = base
        state.pointee.capacity = capacity
    }
    
    /// Write a byte.
    ///
    /// - Parameter byte: The byte.
    @inline(__always)
    func append(_ byte: UInt8) {
        reserve(1)
        state.pointee.base[state.pointee.count] = byte
        state.pointee.count += 1
    }
    
    /// Write ASCII text as it is.
    ///
    /// - Parameter text: The text.
    func write(raw text: StaticString) {
        reserve(text.utf8CodeUnitCount)
        (state.pointee.base + state.pointee.count).update(from: text.utf8Start, count: text.utf8CodeUnitCount)
        state.pointee.count += text.utf8CodeUnitCount
    }
    
    /// Write text as it is.
    ///
    /// - Parameter text: The text.
    func write(raw text: String) {
        var text = text
        text.withUTF8 { utf8 in
            guard let source = utf8.baseAddress else { return }
            reserve(utf8.count)
            (state.pointee.base + state.pointee.count).update(from: source, count: utf8.count)
            state.pointee.count += utf8.count
        }
    }
}


// MARK: - Scalars
extension StreamingJSONEncoder {
    /// Hex digits for `\u00XX` escapes, lowercase as `JSONEncoder` writes them.
    private static let escapeDigits: StaticString = "0123456789abcdef"
    
    /// Write `true` or `false`.
    ///
    /// - Parameter value: The value.
    func write(bool value: Bool) {
        write(raw: value ? "true" as StaticString : "false")
    }
    
    /// Write an integer's decimal digits, with a `-` if it's negative.
    ///
    /// - Parameter value: The integer.
    func write(integer value: some BinaryInteger) {
        if value < 0 { append(UInt8(ascii: "-")) }
        var magnitude = value.magnitude
        /// Room for the 20 digits of `UInt64.max`, written from the end.
        var digits: (UInt64, UInt64, UInt64) = (0, 0, 0)
        withUnsafeMutableBytes(of: &digits) { scratch in
            var index = scratch.count
            repeat {
                index -= 1
                scratch[index] = UInt8(ascii: "0") + UInt8(truncatingIfNeeded: magnitude % 10)
                magnitude /= 10
            } while magnitude != 0
            let count = scratch.count - index
            reserve(count)
            (state.pointee.base + state.pointee.count).update(
                from: scratch.baseAddress!.assumingMemoryBound(to: UInt8.self) + index, count: count)
            state.pointee.count += count
        }
    }
    
    /// Write a number as `JSONEncoder` does: the shortest representation in its own type, without a trailing `.0`. A
    /// `Float` writes its own digits (`0.1`), not those of the `Double` it would widen to (`0.10000000149011612`).
    ///
    /// - Parameter value: The number, such as a `Double` or a `Float`.
    /// - Throws: `EncodingError.invalidValue` for NaN or infinity.
    func write<Number: BinaryFloatingPoint & LosslessStringConvertible>(floating value: Number) throws {
        guard value.isFinite else {
            throw EncodingError.invalidValue(value, .init(codingPath: [], debugDescription: "Non-finite number"))
        }
        var text = value.description
        if text.hasSuffix(".0") { text.removeLast(2) }
        write(raw: text)
    }
    
    /// Write a UUID as its `uuidString` (uppercase), without making the string.
    ///
    /// - Parameter uuid: The UUID.
    func write(uuid: UUID) {
        reserve(38)
        append(UInt8(ascii: "\""))
        withUnsafeBytes(of: uuid.uuid) { bytes in
            (state.pointee.base + state.pointee.count).withMemoryRebound(to: CChar.self, capacity: 37) {
                uuid_unparse_upper(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), $0)
            }
        }
        state.pointee.count += 36
        append(UInt8(ascii: "\""))
    }
    
    /// Write a string, escaped as `JSONEncoder` escapes it: a quote, backslash or slash with a backslash, the usual
    /// control characters by name, other control characters as `\u00XX`, and everything else as its UTF-8.
    ///
    /// - Parameter string: The string.
    func write(string: String) {
        var string = string
        string.withUTF8 { utf8 in
            reserve(utf8.count * 6 + 2)
            var out = state.pointee.base + state.pointee.count
            let start = out
            out.pointee = UInt8(ascii: "\""); out += 1
            for byte in utf8 {
                switch byte {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"):
                    out[0] = UInt8(ascii: "\\"); out[1] = byte; out += 2
                case 0x08: out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "b"); out += 2
                case 0x0c: out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "f"); out += 2
                case 0x0a: out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "n"); out += 2
                case 0x0d: out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "r"); out += 2
                case 0x09: out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "t"); out += 2
                case 0x00..<0x20:
                    out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "u"); out[2] = UInt8(ascii: "0")
                    out[3] = UInt8(ascii: "0")
                    out[4] = Self.escapeDigits.utf8Start[Int(byte >> 4)]
                    out[5] = Self.escapeDigits.utf8Start[Int(byte & 0x0f)]
                    out += 6
                default:
                    out.pointee = byte; out += 1
                }
            }
            out.pointee = UInt8(ascii: "\""); out += 1
            state.pointee.count += out - start
        }
    }
}
