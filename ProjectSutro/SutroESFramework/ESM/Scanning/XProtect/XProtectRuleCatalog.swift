//
//  XProtectRuleCatalog.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - One rule
/// One of Apple's XProtect rules that Mac Monitor scans written files with, as its rule file writes it.
public struct XProtectRule: Identifiable, Equatable, Sendable {
    /// The rule's identifier, such as `XProtect_MACOS_OSASCRIPT_BOTEA`.
    public let identifier: String
    /// XProtect's name for it, its meta `description`, such as `MACOS.OSASCRIPT.BOTEA`. A rule without one is named
    /// by its identifier, as `yara_scan` names it.
    public let name: String
    /// Its meta `uuid`, or `nil` without one.
    public let uuid: String?
    /// Does XProtect only report it and never act on it (`match_type = 4`)?
    public let isReportOnly: Bool
    /// The rule file it's in.
    public let file: XProtectRuleFile
    /// The rule as written, from its header line to its closing brace.
    public let source: String

    /// The file and the identifier, which is unique in a catalog.
    public var id: String { "\(file.rawValue)/\(identifier)" }
}


// MARK: - The catalog
/// The rules Mac Monitor scans written files with, from the XProtect bundle the Security Extension scans with
/// (``XProtectRuleSources``). Private and global rules aren't listed. They only help the others match.
///
/// A rule starts at a header at the start of a line, as Apple writes every rule, and ends at the last closing brace
/// before the next header. No brace is counted, so strings, hex strings, regexes and comments may hold any. A rule's
/// metas are read up to its strings or its condition.
public struct XProtectRuleCatalog: Sendable {
    /// The XProtect version, such as `5377`.
    public let version: String
    /// The rules in each file's order, `XProtect.yara`'s first.
    public let rules: [XProtectRule]

    /// A rule's header: its modifiers, then its identifier.
    private static let header = try! NSRegularExpression(
        pattern: #"^((?:(?:private|global)\s+)*)rule\s+(\w+)"#, options: .anchorsMatchLines)
    /// What a meta section holds: a comment, the start of the strings or condition (1), or a meta's name (2) with
    /// its text (3) or its number or boolean (4).
    private static let meta = try! NSRegularExpression(pattern: #"//[^\n]*|/\*[\s\S]*?\*/|\b(strings|condition)\s*:"#
        + #"|(?<![\w$])(\w+)\s*=\s*(?:"((?:[^"\\\n]|\\.)*)"|(-?\w+))"#)

    /// Reads this Mac's rules from the bundle the Security Extension scans with. It reads and parses about 1 MB, so
    /// call it off the main thread.
    ///
    /// - Returns: The catalog, or `nil` when no XProtect bundle has its rules.
    public static func read() -> XProtectRuleCatalog? {
        XProtectRuleSources.read().map(XProtectRuleCatalog.init)
    }

    /// - Parameter sources: The bundle's rule files.
    init(_ sources: XProtectRuleSources) {
        version = sources.version
        rules = XProtectRuleFile.allCases.flatMap { file in
            sources.texts[file].map { Self.rules(in: String(decoding: $0, as: UTF8.self), file: file) } ?? []
        }
    }

    /// The listed rules in one rule file's text.
    ///
    /// - Parameters:
    ///   - text: The file's text.
    ///   - file: Which file it is.
    /// - Returns: Its rules but the private and global ones, in order.
    static func rules(in text: String, file: XProtectRuleFile) -> [XProtectRule] {
        let text = NSString(string: text)
        let headers = header.matches(in: text as String, range: NSRange(location: 0, length: text.length))
        return headers.indices.compactMap { index in
            let found = headers[index]
            let start = found.range.location
            let end = index + 1 < headers.count ? headers[index + 1].range.location : text.length
            let close = text.range(of: "}", options: .backwards, range: NSRange(location: start, length: end - start))
            guard found.range(at: 1).length == 0, close.location != NSNotFound else { return nil }
            let source = text.substring(with: NSRange(location: start, length: NSMaxRange(close) - start))
            let identifier = text.substring(with: found.range(at: 2))
            let metas = metas(in: source)
            return XProtectRule(identifier: identifier, name: metas["description"] ?? identifier, uuid: metas["uuid"],
                                isReportOnly: metas["match_type"] == "4", file: file, source: source)
        }
    }

    /// A rule's metas by name, as written. A repeated name keeps its first.
    ///
    /// - Parameter source: The rule.
    /// - Returns: Each meta's text, number or boolean.
    static func metas(in source: String) -> [String: String] {
        let text = NSString(string: source)
        var metas: [String: String] = [:]
        meta.enumerateMatches(in: text as String, range: NSRange(location: 0, length: text.length)) { match, _, stop in
            guard let match else { return }
            if match.range(at: 1).location != NSNotFound { return stop.pointee = true }
            guard match.range(at: 2).location != NSNotFound,
                  let value = [3, 4].map(match.range(at:)).first(where: { $0.location != NSNotFound }) else { return }
            let name = text.substring(with: match.range(at: 2))
            if metas[name] == nil { metas[name] = text.substring(with: value) }
        }
        return metas
    }
}
