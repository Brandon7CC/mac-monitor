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
    /// Where `JSONEncoder` writes other digits (``State/leavesFloatsToJSONEncoder``), the value is left to it.
    ///
    /// - Parameter value: The number, such as a `Double` or a `Float`.
    /// - Throws: `EncodingError.invalidValue` for NaN or infinity.
    func write<Number: BinaryFloatingPoint & LosslessStringConvertible>(floating value: Number) throws {
        guard value.isFinite else {
            throw EncodingError.invalidValue(value, .init(codingPath: [], debugDescription: "Non-finite number"))
        }
        guard !state.pointee.leavesFloatsToJSONEncoder else {
            state.pointee.isUnstreamable = true
            return write(raw: "0" as StaticString)
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
    
    /// Write a string, escaped as `JSONEncoder` escapes it: a quote, backslash or slash (unless the encoder leaves
    /// slashes alone) with a backslash, the usual control characters by name, other control characters as `\u00XX`,
    /// and everything else as its UTF-8.
    ///
    /// Most of a record's strings need no escaping, so eight bytes at a time are tested together and, when none of
    /// them needs escaping, copied together (``needsEscaping(_:slashes:)``). The rest go one byte at a time
    /// (``escape(_:slashes:into:)``), which writes what this always wrote.
    ///
    /// - Parameter string: The string.
    func write(string: String) {
        var string = string
        let escapesSlashes = state.pointee.escapesSlashes
        string.withUTF8 { utf8 in
            reserve(utf8.count * 6 + 2)
            var out = state.pointee.base + state.pointee.count
            let start = out
            out.pointee = UInt8(ascii: "\""); out += 1
            var index = 0
            if let bytes = UnsafeRawPointer(utf8.baseAddress) {
                while index &+ 8 <= utf8.count {
                    let word = bytes.loadUnaligned(fromByteOffset: index, as: UInt64.self)
                    if Self.needsEscaping(word, slashes: escapesSlashes) {
                        for offset in 0..<8 {
                            out = Self.escape(utf8[index &+ offset], slashes: escapesSlashes, into: out)
                        }
                    } else {
                        UnsafeMutableRawPointer(out).copyMemory(from: bytes + index, byteCount: 8)
                        out += 8
                    }
                    index &+= 8
                }
            }
            while index < utf8.count {
                out = Self.escape(utf8[index], slashes: escapesSlashes, into: out)
                index &+= 1
            }
            out.pointee = UInt8(ascii: "\""); out += 1
            state.pointee.count += out - start
        }
    }

    /// Does any of eight bytes need escaping: a control character, a quote, a backslash, or a slash when slashes are
    /// escaped? Each test is the usual one for a byte below a value, or equal to one, anywhere in a word, and is
    /// exact: it's nonzero only when such a byte is there. A byte of a scalar that isn't ASCII has its high bit set,
    /// and is none of them.
    ///
    /// - Parameters:
    ///   - word: Eight of a string's UTF-8 bytes, in any order.
    ///   - slashes: Are slashes escaped?
    /// - Returns: Whether at least one needs escaping.
    @inline(__always)
    private static func needsEscaping(_ word: UInt64, slashes: Bool) -> Bool {
        let ones: UInt64 = 0x0101_0101_0101_0101, highs: UInt64 = 0x8080_8080_8080_8080
        /// - Parameter byte: A byte below 0x80.
        /// - Returns: Nonzero when a byte of the word is `byte`.
        func has(_ byte: UInt64) -> UInt64 {
            let difference = word ^ (ones &* byte)
            return (difference &- ones) & ~difference & highs
        }
        var found = (word &- ones &* 0x20) & ~word & highs
        found |= has(0x22) | has(0x5C)
        if slashes { found |= has(0x2F) }
        return found != 0
    }

    /// Write one byte of a string, escaped if it has to be.
    ///
    /// - Parameters:
    ///   - byte: The byte.
    ///   - slashes: Are slashes escaped?
    ///   - out: Where to write, with room for six bytes.
    /// - Returns: Where the next byte goes.
    @inline(__always)
    private static func escape(_ byte: UInt8, slashes: Bool,
                               into out: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
        /// - Parameter letter: An escape's letter.
        /// - Returns: Where the next byte goes, after a backslash and the letter.
        func short(_ letter: UInt8) -> UnsafeMutablePointer<UInt8> {
            out[0] = UInt8(ascii: "\\"); out[1] = letter
            return out + 2
        }
        switch byte {
        case UInt8(ascii: "\""), UInt8(ascii: "\\"): return short(byte)
        case UInt8(ascii: "/") where slashes: return short(byte)
        case 0x08: return short(UInt8(ascii: "b"))
        case 0x0c: return short(UInt8(ascii: "f"))
        case 0x0a: return short(UInt8(ascii: "n"))
        case 0x0d: return short(UInt8(ascii: "r"))
        case 0x09: return short(UInt8(ascii: "t"))
        case 0x00..<0x20:
            out[0] = UInt8(ascii: "\\"); out[1] = UInt8(ascii: "u"); out[2] = UInt8(ascii: "0")
            out[3] = UInt8(ascii: "0")
            out[4] = escapeDigits.utf8Start[Int(byte >> 4)]
            out[5] = escapeDigits.utf8Start[Int(byte & 0x0f)]
            return out + 6
        default:
            out.pointee = byte
            return out + 1
        }
    }
}
