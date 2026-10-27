//
//  ProcessHelpers+Quarantine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - File Quarantine
extension ProcessHelpers {
    /// Returns 1 if the file is quarantined, 0 if not, and 2 if the file is not found
    ///
    /// One `getxattr(2)` answers in the common cases: the attribute's size, `ENOATTR` (a file without one), or `ENOENT`
    /// and `ENOTDIR` (no file). Only another error asks `FileManager` whether the file exists, which it used to ask
    /// first for every file.
    ///
    /// - Parameter filePath: The file's path. A symbolic link is followed, as `fileExists(atPath:)` follows it.
    /// - Returns: 1, 0, or 2.
    public static func isFileQuarantined(filePath: String) -> Int {
        /// A path with a NUL is answered as before: `getxattr` reads it up to the NUL, and `fileExists(atPath:)` has
        /// rules of its own for one.
        guard !filePath.utf8.contains(0) else {
            guard FileManager.default.fileExists(atPath: filePath) else { return 2 }
            return getxattr(filePath, "com.apple.quarantine", nil, 0, 0, 0) > 0 ? 1 : 0
        }
        let size = getxattr(filePath, "com.apple.quarantine", nil, 0, 0, 0)
        if size >= 0 { return size > 0 ? 1 : 0 }
        switch errno {
        case ENOATTR: return 0
        case ENOENT, ENOTDIR: return 2
        default: return FileManager.default.fileExists(atPath: filePath) ? 0 : 2
        }
    }
    
    
    // MARK: - LSFileQuarantineEnabled check
    
    /// Which bundle identifiers are forced into File Quarantine?
    ///
    /// Bundle identifiers forced into File Quarantine by Apple are located in a property list file by the name of
    /// `Exceptions.plist`. We read from that property list and pull out all identifiers with a
    /// `LSFileQuarantineEnabled` key value set to `true`.
    ///
    public static let forcedQuarantineSigningIDs: [String] = {
        let path = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/Exceptions.plist"
        guard let additions = NSDictionary(contentsOfFile: path)?["Additions"] as? [String: Any] else { return [] }
        return additions.keys.filter { (additions[$0] as? [String: Any])?["LSFileQuarantineEnabled"] != nil }
    }()
    
    /// Does a path have the bytes of ".app" anywhere in its UTF-8?
    ///
    /// Foundation's `contains(".app")` is a non-literal search: it matches whole characters by canonical equivalence.
    /// No character but the ASCII ones themselves is canonically equivalent to ".", "a" or "p" (and a letter with a
    /// combining mark is a different character), so every path it finds ".app" in has these bytes. The converse
    /// doesn't hold (".app" followed by a combining mark), so a path that has them is still asked of `contains`.
    ///
    /// - Parameter path: The path.
    /// - Returns: `true` if the bytes `.app` appear in it.
    static func hasAppBytes(_ path: String) -> Bool {
        var path = path
        return path.withUTF8 { bytes in
            guard bytes.count >= 4 else { return false }
            for index in 0...(bytes.count - 4) where bytes[index] == UInt8(ascii: ".") {
                if bytes[index + 1] == UInt8(ascii: "a"), bytes[index + 2] == UInt8(ascii: "p"),
                   bytes[index + 3] == UInt8(ascii: "p") { return true }
            }
            return false
        }
    }
    
    /// The cache we use for paths we've already checked
    private static let quarantineCheckCache: NSCache<NSString, NSNumber> = {
        let cache = NSCache<NSString, NSNumber>()
        cache.countLimit = 1000
        return cache
    }()
    
    /// Given the path to an executable on-disk return if it's "File Quarantine-aware".
    ///
    /// This method checks if an executable application has the `LSFileQuarantineEnabled` key
    /// set to `true` in its Info.plist file. Applications with this flag enabled respect in file quarantine.
    ///
    /// - Parameter path: The file path to the executable to check
    /// - Returns: `true` if the executable has quarantine enabled, `false` otherwise
    ///
    /// The method uses an internal cache to avoid repeated disk access and plist parsing
    /// for paths that have already been checked. The cache has a limit of 1000 entries.
    public static func isQuarantineEnabled(forExecutableAt path: String, signingId: String?) -> FileQuarantineType {
        /// We're only going to check for File Quarantine with app bundles. A path without the bytes of ".app" is
        /// turned away before Foundation's `contains` (~2 µs), which can only find ".app" where they are.
        if !hasAppBytes(path) || !path.contains(".app") {
            return .disabled
        }
        
        /// First, check if Apple has forced the executable into being File Quarantine-aware
        if let signingId, forcedQuarantineSigningIDs.contains(signingId) {
            return .forced
        }
        
        /// Second, check if the path is in the cache
        let nsPath = path as NSString
        if let cached = quarantineCheckCache.object(forKey: nsPath) {
            return cached.boolValue ? .optIn : .disabled
        }
        
        /// Third, check if `LSFileQuarantineEnabled` is in the bundle's Info.plist, and cache what's found: a path
        /// without `Contents`, or a plist that's missing or doesn't set it, is disabled.
        let components = URL(fileURLWithPath: path).pathComponents
        let plist = components.firstIndex(of: "Contents").map {
            NSString.path(withComponents: Array(components.prefix(through: $0)) + ["Info.plist"])
        }
        let enabled = plist.flatMap { NSDictionary(contentsOfFile: $0)?["LSFileQuarantineEnabled"] as? Bool } ?? false
        quarantineCheckCache.setObject(NSNumber(value: enabled), forKey: nsPath)
        return enabled ? .optIn : .disabled
    }
}
