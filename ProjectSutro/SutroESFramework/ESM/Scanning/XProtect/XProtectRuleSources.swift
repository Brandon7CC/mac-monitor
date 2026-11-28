//
//  XProtectRuleSources.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation
import CryptoKit


// MARK: - Apple's rule files
/// One of the two YARA rule files XProtect ships, and what Mac Monitor scans with it.
///
/// XProtect evaluates them apart: `XProtect.yara` for files it assesses, and `XPScripts.yr` for what `osascript` runs
/// (assessment class 4). Mac Monitor keeps the same split. Each file compiles into a rule set of its own, as the two
/// share a rule identifier (`OSACompiledJXA`).
public enum XProtectRuleFile: String, CaseIterable, Sendable {
    /// The rules for Mach-O files and the other files XProtect assesses.
    case xprotect = "XProtect.yara"
    /// The rules for AppleScript and JavaScript for Automation that `osascript` runs.
    case scripts = "XPScripts.yr"

    /// Names the file's rule set in file names, such as `XProtect`.
    var stem: String { (rawValue as NSString).deletingPathExtension }
}


// MARK: - Reading them
/// Apple's rule files as one XProtect bundle has them, with the bundle's version and a digest of each file.
///
/// macOS 13 has one bundle, in `/Library/Apple`. Later releases also update a second in `/var/protected/xprotect`,
/// which XProtect reads first. Mac Monitor takes whichever bundle's version is higher, as XProtect does.
struct XProtectRuleSources: Equatable, Sendable {
    /// The bundles to choose from, most preferred first when their versions tie.
    static let bundles = [
        URL(fileURLWithPath: "/var/protected/xprotect/XProtect.bundle", isDirectory: true),
        URL(fileURLWithPath: "/Library/Apple/System/Library/CoreServices/XProtect.bundle", isDirectory: true),
    ]

    /// The largest rule file read. XProtect.yara is about 1 MB.
    static let maxBytes = 16 << 20

    /// The bundle the files were read from.
    let bundle: URL
    /// Its `CFBundleShortVersionString`, such as `5377`.
    let version: String
    /// Each file's text, for the files the bundle has.
    let texts: [XProtectRuleFile: Data]

    /// A file's SHA-256, as hex.
    ///
    /// - Parameter file: The file.
    /// - Returns: The digest, or `nil` when the bundle doesn't have it.
    func digest(of file: XProtectRuleFile) -> String? {
        texts[file].map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() }
    }

    /// Reads the bundle with the highest version that has `XProtect.yara`.
    ///
    /// - Parameter bundles: The bundles to choose from.
    /// - Returns: The sources, or `nil` when no bundle has its rules.
    static func read(from bundles: [URL] = bundles) -> XProtectRuleSources? {
        let candidates = bundles.compactMap(read(bundle:))
        return candidates.enumerated().max { left, right in
            let order = left.element.version.compare(right.element.version, options: .numeric)
            /// On a tie the earlier bundle wins, so it must compare as the larger.
            return order == .orderedAscending || (order == .orderedSame && left.offset > right.offset)
        }?.element
    }

    /// Reads one bundle.
    ///
    /// - Parameter bundle: The bundle.
    /// - Returns: Its sources, or `nil` when it has no version or no `XProtect.yara`.
    private static func read(bundle: URL) -> XProtectRuleSources? {
        let contents = bundle.appendingPathComponent("Contents", isDirectory: true)
        guard let info = NSDictionary(contentsOf: contents.appendingPathComponent("Info.plist")),
              let version = info["CFBundleShortVersionString"] as? String else { return nil }
        let resources = contents.appendingPathComponent("Resources", isDirectory: true)
        var texts: [XProtectRuleFile: Data] = [:]
        for file in XProtectRuleFile.allCases {
            texts[file] = readFile(resources.appendingPathComponent(file.rawValue))
        }
        guard texts[.xprotect] != nil else { return nil }
        return XProtectRuleSources(bundle: bundle, version: version, texts: texts)
    }

    /// A rule file's bytes, when it's a regular file of at most ``maxBytes``.
    ///
    /// - Parameter url: The file.
    /// - Returns: The bytes, or `nil`.
    private static func readFile(_ url: URL) -> Data? {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size <= off_t(maxBytes) else { return nil }
        return try? file.read(upToCount: maxBytes)
    }
}
