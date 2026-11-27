//
//  JSONOutline+Scanning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Scanning
public extension JSONOutline {
    /// Outline a JSON text in one pass over its UTF-16 units.
    ///
    /// - Parameter text: The text, which needn't be whole or valid JSON.
    init(_ text: String) {
        var scanner = OutlineScanner()
        for unit in text.utf16 { scanner.read(unit) }
        self = scanner.finish()
    }
}


// MARK: - Scanner
/// The one pass ``JSONOutline/init(_:)`` makes, a UTF-16 unit at a time.
private struct OutlineScanner {
    /// What the text holds next.
    enum Expecting { case value, key, colon, separator }

    /// What a string being read is.
    enum StringRole { case key, value(Int), stray }

    var outline = JSONOutline()
    var lineStarts = [0]
    var offset = 0
    var expecting = Expecting.value
    /// The containers open, innermost last.
    var stack: [Int] = []
    /// The string being read, and where it started.
    var string: (start: Int, role: StringRole)?
    /// Was the last unit in the string a backslash, which escapes this one?
    var escaped = false
    /// The key being read, and whether it has an escape.
    var keyUnits: [UInt16] = []
    var keyHasEscape = false
    /// The key read, waiting for its value.
    var key: (range: NSRange, name: String)?
    /// The number, `true`, `false` or `null` being read, by its value.
    var scalar: Int?

    /// Does a value start here? Where one is expected, or anywhere at the top, as in JSON Lines.
    var takesValue: Bool { expecting == .value || stack.isEmpty }

    /// Read the next unit.
    ///
    /// - Parameter unit: The UTF-16 unit.
    mutating func read(_ unit: UInt16) {
        defer {
            offset += 1
            if unit == 0x0A { lineStarts.append(offset) }
        }
        if let string {
            readString(unit, string)
            return
        }
        if let scalar {
            guard Self.delimiters.contains(unit) else { return }
            outline.values[scalar].range.length = offset - outline.values[scalar].range.location
            self.scalar = nil
            expecting = .separator
        }
        switch unit {
        case 0x22:
            beginString()
        case 0x7B, 0x5B:
            open(isArray: unit == 0x5B)
        case 0x7D, 0x5D:
            close(isArray: unit == 0x5D)
        case 0x3A:
            if expecting == .colon { expecting = .value }
        case 0x2C:
            guard expecting == .separator, let top = stack.last else { break }
            expecting = outline.containers[top].isArray ? .value : .key
        default:
            if takesValue, let kind = Self.scalarKinds[unit] { scalar = append(kind) }
        }
    }

    /// The units that end a number, `true`, `false` or `null`: white space and JSON's punctuation.
    static let delimiters: Set<UInt16> = [0x20, 0x09, 0x0A, 0x0D, 0x2C, 0x3A, 0x22, 0x7B, 0x7D, 0x5B, 0x5D]

    /// The units a number, `true`, `false` or `null` starts with, and the kind each starts.
    static let scalarKinds: [UInt16: JSONOutline.Kind] = {
        var kinds: [UInt16: JSONOutline.Kind] = [0x74: .boolean, 0x66: .boolean, 0x6E: .null, 0x2D: .number]
        for digit in UInt16(0x30)...0x39 { kinds[digit] = .number }
        return kinds
    }()

    /// Start a string: a key where one goes, a value where one goes, else stray text whose brackets are skipped.
    mutating func beginString() {
        if expecting == .key {
            keyUnits.removeAll(keepingCapacity: true)
            keyHasEscape = false
            string = (offset, .key)
        } else {
            string = (offset, takesValue ? .value(append(.string)) : .stray)
        }
    }

    /// Read a unit of a string, which ends at a quote no backslash escapes.
    ///
    /// - Parameters:
    ///   - unit: The unit.
    ///   - string: The string, and where it started.
    mutating func readString(_ unit: UInt16, _ string: (start: Int, role: StringRole)) {
        let isKey: Bool
        if case .key = string.role { isKey = true } else { isKey = false }
        guard escaped || unit != 0x22 else {
            self.string = nil
            let range = NSRange(location: string.start, length: offset + 1 - string.start)
            switch string.role {
            case .key:
                key = (range, Self.name(keyUnits, escaped: keyHasEscape))
                expecting = .colon
            case .value(let index):
                outline.values[index].range = range
                expecting = .separator
            case .stray:
                break
            }
            return
        }
        if isKey {
            keyUnits.append(unit)
            keyHasEscape = keyHasEscape || unit == 0x5C
        }
        escaped = !escaped && unit == 0x5C
    }

    /// Open an object or an array where a value goes. A bracket anywhere else is skipped.
    ///
    /// - Parameter isArray: Is it an array?
    mutating func open(isArray: Bool) {
        guard takesValue else { return }
        let value = append(isArray ? .array : .object)
        let line = lineStarts.count - 1
        outline.containers.append(JSONOutline.Container(isArray: isArray, open: offset, close: nil, startLine: line,
                                                        endLine: line, value: value))
        stack.append(outline.containers.count - 1)
        expecting = isArray ? .value : .key
    }

    /// Close the innermost container, if it's the kind the bracket closes. A bracket that doesn't is skipped.
    ///
    /// - Parameter isArray: Does an array's bracket close it?
    mutating func close(isArray: Bool) {
        guard let top = stack.last, outline.containers[top].isArray == isArray else { return }
        stack.removeLast()
        outline.containers[top].close = offset
        outline.containers[top].endLine = lineStarts.count - 1
        let value = outline.containers[top].value
        outline.values[value].range.length = offset + 1 - outline.values[value].range.location
        expecting = .separator
    }

    /// Add a value that starts here, in the innermost container open, under the key just read.
    ///
    /// - Parameter kind: What it is.
    /// - Returns: The value, in ``JSONOutline/values``.
    mutating func append(_ kind: JSONOutline.Kind) -> Int {
        let parent = stack.last
        var keyPath = "", isInArray = false, member: NSRange?
        if let parent {
            let container = outline.containers[parent]
            let around = outline.values[container.value]
            isInArray = container.isArray || around.isInArray
            if container.isArray {
                keyPath = around.keyPath
            } else {
                member = key?.range
                let name = key?.name ?? ""
                keyPath = around.keyPath.isEmpty ? name : around.keyPath + "." + name
            }
            outline.containers[parent].count += 1
        }
        key = nil
        let isContainer = kind == .object || kind == .array
        outline.values.append(JSONOutline.Value(kind: kind, key: member, range: NSRange(location: offset, length: 1),
                                                keyPath: keyPath, isInArray: isInArray, parent: parent,
                                                container: isContainer ? outline.containers.count : nil))
        return outline.values.count - 1
    }

    /// End the pass: whatever is still open runs to the end of the text.
    ///
    /// - Returns: The outline.
    mutating func finish() -> JSONOutline {
        let lastLine = lineStarts.count - 1
        var open = stack.map { outline.containers[$0].value }
        if let scalar { open.append(scalar) }
        if let string, case .value(let index) = string.role { open.append(index) }
        for index in open {
            outline.values[index].range.length = offset - outline.values[index].range.location
        }
        for index in stack { outline.containers[index].endLine = lastLine }
        outline.lines = TextLines(starts: lineStarts, length: offset)
        for (index, container) in outline.containers.enumerated().reversed() where container.isFoldable {
            outline.foldable[container.startLine] = index
        }
        return outline
    }

    /// A key's name.
    ///
    /// - Parameters:
    ///   - units: The key's units, between its quotes.
    ///   - escaped: Does it have a backslash?
    /// - Returns: The name, with its escapes read when it has any.
    static func name(_ units: [UInt16], escaped: Bool) -> String {
        let raw = String(decoding: units, as: UTF16.self)
        guard escaped else { return raw }
        return JSONOutline.unescaped("\"" + raw + "\"") ?? raw
    }
}
