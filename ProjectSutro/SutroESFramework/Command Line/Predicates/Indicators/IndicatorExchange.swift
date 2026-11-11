//
//  IndicatorExchange.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Sharing indicators
/// Indicators as a JSON file to share: Settings > Indicators exports the ones it shows, or one, and imports a file
/// another Mac exported. The file names its format and version, then lists each indicator as Mac Monitor saves it:
///
/// ```json
/// { "format": "com.swiftlydetecting.indicators", "version": 1, "indicators": [ { "name": "...", ... } ] }
/// ```
///
/// A bare array of indicators, or one indicator alone, imports too.
public enum IndicatorExchange {
    /// What the file says it is.
    public static let format = "com.swiftlydetecting.indicators"
    /// The file's version. A newer one isn't read, since its indicators may mean more than this build knows.
    public static let version = 1

    /// Why a file can't be imported.
    public struct ImportError: LocalizedError, Equatable {
        public let message: String
        public var errorDescription: String? { message }

        /// - Parameter message: Why, as a sentence.
        public init(message: String) {
            self.message = message
        }
    }

    /// The file's top level.
    private struct File: Codable {
        let format: String
        let version: Int
        let indicators: [Indicator]
    }

    /// - Parameter indicators: The indicators, in the order they're listed.
    /// - Returns: The file, pretty-printed with its keys sorted, so a shared file reads and diffs well.
    /// - Throws: The encoder's error.
    public static func data(of indicators: [Indicator]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(File(format: format, version: version, indicators: indicators))
    }

    /// - Parameter data: A file of indicators.
    /// - Returns: Its indicators, in its order.
    /// - Throws: ``ImportError`` when it isn't JSON of indicators, is another format, is a newer version, or has
    ///   none.
    public static func indicators(from data: Data) throws -> [Indicator] {
        let object = try checkedJSON(data)
        let decoder = JSONDecoder()
        let indicators: [Indicator]
        if isFile(object) {
            indicators = try decoded { try decoder.decode(File.self, from: data).indicators }
        } else if object is [Any] {
            indicators = try decoded { try decoder.decode([Indicator].self, from: data) }
        } else {
            indicators = try decoded { [try decoder.decode(Indicator.self, from: data)] }
        }
        guard !indicators.isEmpty else { throw ImportError(message: "The file has no indicators.") }
        return indicators
    }

    /// The most bytes a file may have to be imported: the Mac's whole indicator set saved.
    public static let maxFileBytes = IndicatorLimits.maxFileBytes

    /// Read a file someone chose to import, as Settings > Indicators' Import does: a regular file, at most
    /// ``maxFileBytes``, checked before it's read.
    ///
    /// - Parameter url: The file.
    /// - Returns: Its indicators, in its order.
    /// - Throws: ``ImportError`` when it isn't a regular file, is too large, or isn't a file of indicators, or the
    ///   error reading it.
    public static func indicators(contentsOf url: URL) throws -> [Indicator] {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else { throw ImportError(message: "Only a file can be imported.") }
        let tooLarge = ImportError(message: "The file is over \(maxFileBytes >> 20) MiB, the most Import reads.")
        guard (values.fileSize ?? 0) <= maxFileBytes else { throw tooLarge }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maxFileBytes + 1) ?? Data()
        guard data.count <= maxFileBytes else { throw tooLarge }
        return try indicators(from: data)
    }

    /// A file's JSON, with its format and version checked when it names them.
    ///
    /// - Parameter data: A file of indicators.
    /// - Returns: Its JSON, as `JSONSerialization` reads it.
    /// - Throws: ``ImportError`` when it isn't JSON, is another format, or is a newer version.
    static func checkedJSON(_ data: Data) throws -> Any {
        guard let object = try? JSONSerialization.jsonObject(with: data) else {
            throw ImportError(message: "The file isn't JSON.")
        }
        guard isFile(object), let file = object as? [String: Any] else { return object }
        guard file["format"] as? String == format else {
            throw ImportError(message: "The file isn't Mac Monitor indicators.")
        }
        guard let fileVersion = file["version"] as? Int, fileVersion <= version else {
            throw ImportError(message: "The file is from a newer Mac Monitor. Update to import it.")
        }
        return object
    }

    /// - Parameter object: A file's JSON.
    /// - Returns: `true` when it's the file ``data(of:)`` writes, which names its format and lists `indicators`,
    ///   rather than a bare array or one indicator.
    static func isFile(_ object: Any) -> Bool {
        guard let file = object as? [String: Any] else { return false }
        return file["indicators"] != nil || file["format"] != nil
    }

    /// - Parameter decode: Decodes the indicators.
    /// - Returns: What it decoded.
    /// - Throws: ``ImportError`` naming what's missing or wrong, for a decoding error.
    static func decoded(_ decode: () throws -> [Indicator]) throws -> [Indicator] {
        do {
            return try decode()
        } catch let DecodingError.keyNotFound(key, _) {
            throw ImportError(message: "An indicator in the file has no \(key.stringValue).")
        } catch let DecodingError.typeMismatch(_, context), let DecodingError.valueNotFound(_, context) {
            let path = context.codingPath.filter { $0.intValue == nil }.map(\.stringValue).joined(separator: ".")
            throw ImportError(message: "An indicator in the file has a value for \(path) that can't be read.")
        } catch let DecodingError.dataCorrupted(context) {
            throw ImportError(message: "An indicator in the file can't be read: \(context.debugDescription)")
        } catch {
            throw ImportError(message: "The file's indicators can't be read.")
        }
    }

    /// Merge imported indicators into a list: one with an identity already listed replaces it, in its place, and the
    /// rest are added at the end, in the file's order.
    ///
    /// - Parameters:
    ///   - imported: The file's indicators.
    ///   - indicators: The indicators now.
    /// - Returns: The merged list, and how many were added and how many replaced.
    public static func merge(_ imported: [Indicator], into indicators: [Indicator])
        -> (indicators: [Indicator], added: Int, replaced: Int) {
        var merged = indicators, added = 0, replaced = 0
        for indicator in imported {
            if let index = merged.firstIndex(where: { $0.id == indicator.id }) {
                merged[index] = indicator
                replaced += 1
            } else {
                merged.append(indicator)
                added += 1
            }
        }
        return (merged, added, replaced)
    }
}
