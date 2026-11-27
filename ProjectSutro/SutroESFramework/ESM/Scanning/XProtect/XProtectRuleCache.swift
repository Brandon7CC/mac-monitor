//
//  XProtectRuleCache.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation
import CryptoKit


// MARK: - Compiled rules on disk
/// Apple's rule files compiled once and kept in the Security Extension's root-only directory (``RootFileStore``), one
/// file per rule file, such as `xprotect-XProtect-<key>.yarc`.
///
/// A file's key is a digest of what it was compiled from and with: the rule file's text, the libyara layout and this
/// macOS build. An XProtect update or a macOS update gives a new key, so stale rules are never loaded, and the old
/// file is removed once the new one is written. Loading compiled rules from a file only root can write is safe:
/// anyone who could replace it is already root.
struct XProtectRuleCache: Sendable {
    /// The largest compiled rule file kept. XProtect.yara compiles to 8 MB on macOS 27 and 36 MB on 13.
    static let maxBytes = 128 << 20

    /// The directory, root-only in the Security Extension.
    let directory: URL
    /// Who must own it and its files.
    let owner: uid_t

    /// - Parameters:
    ///   - directory: The directory.
    ///   - owner: Who must own it: root, or the user running a test.
    init(directory: URL = RootFileStore.systemDirectory, owner: uid_t = 0) {
        self.directory = directory
        self.owner = owner
    }

    /// The key for a rule file's compiled rules.
    ///
    /// - Parameters:
    ///   - file: The rule file.
    ///   - digest: The SHA-256 of its text.
    ///   - abi: The libyara layout that compiles it.
    ///   - build: This macOS build, such as `26B131`.
    /// - Returns: 16 hex digits.
    static func key(for file: XProtectRuleFile, digest: String, abi: YaraABI, build: String) -> String {
        let parts = [file.rawValue, digest, abi.generation.rawValue, String(abi.identifierOffset), build]
        let hash = SHA256.hash(data: Data(parts.joined(separator: "\n").utf8))
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// This Mac's macOS build (`kern.osversion`).
    static var currentBuild: String {
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else { return "unknown" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &buffer, &size, nil, 0) == 0 else { return "unknown" }
        return String(cString: buffer)
    }

    /// What a rule file's compiled rules are called, without the key.
    ///
    /// - Parameter file: The rule file.
    /// - Returns: Such as `xprotect-XProtect-`.
    private static func prefix(of file: XProtectRuleFile) -> String { "xprotect-\(file.stem)-" }

    /// The store for one key's compiled rules.
    ///
    /// - Parameters:
    ///   - file: The rule file.
    ///   - key: The key.
    /// - Returns: The store.
    func store(for file: XProtectRuleFile, key: String) -> RootFileStore {
        let name = Self.prefix(of: file) + key
        let layout = RootFileStore.Layout(fileName: name + ".yarc", unreadableFileName: name + ".unreadable.yarc",
                                          temporaryPrefix: "." + Self.prefix(of: file), maxBytes: Self.maxBytes,
                                          noun: "compiled \(file.rawValue) rules")
        return RootFileStore(directory: directory, owner: owner, layout: layout)
    }

    /// Loads a key's compiled rules, when they're kept.
    ///
    /// - Parameters:
    ///   - file: The rule file.
    ///   - key: The key.
    ///   - library: The library that compiled them.
    /// - Returns: The rules, or `nil` when none are kept or they don't load. Ones that don't load are moved aside.
    func load(_ file: XProtectRuleFile, key: String, library: YaraLibrary) -> YaraRuleSet? {
        let store = store(for: file, key: key)
        guard case .opened(let handle)? = try? store.openForReading() else { return nil }
        guard let rules = try? YaraRuleSet.load(from: handle.fileDescriptor, library: library) else {
            _ = store.moveAside()
            return nil
        }
        return rules
    }

    /// Removes a rule file's compiled rules for every other key, and what was moved aside.
    ///
    /// - Parameters:
    ///   - file: The rule file.
    ///   - key: The key to keep.
    func prune(_ file: XProtectRuleFile, keeping key: String) {
        let keep = store(for: file, key: key).layout.fileName
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names where name.hasPrefix(Self.prefix(of: file)) && name != keep {
            unlink(directory.appendingPathComponent(name).path)
        }
    }
}
