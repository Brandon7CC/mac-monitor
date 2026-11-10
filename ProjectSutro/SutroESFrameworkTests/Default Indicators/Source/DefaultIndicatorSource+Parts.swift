//
//  DefaultIndicatorSource+Parts.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Credential access
extension Indicator {
    /// The daemons that open keychain files as their work: securityd and its system instance, secd for the data
    /// protection keychain, and trustd for certificates. They're on the sealed system volume, so a path is theirs.
    static let keychainDaemons = ["/usr/sbin/securityd", "/usr/libexec/securityd_system", "/usr/libexec/secd",
                                  "/usr/libexec/trustd"]
}

// MARK: - Persistence
extension Indicator {
    /// The zsh startup files, without their leading dot: `~/.zshrc` in a home folder, `zshrc` in `/private/etc`.
    static let zshStartupFiles = ["zshenv", "zprofile", "zshrc", "zlogin", "zlogout"]
    /// The folders a macOS host loads plug-ins from, in `/Library` or a home folder's `Library`, and the extension of
    /// the bundles it loads.
    static let pluginFolders: [(folder: String, suffix: String)] = [
        ("Screen Savers", ".saver"), ("Spotlight", ".mdimporter"), ("ColorPickers", ".colorPicker"),
        ("PreferencePanes", ".prefPane"), ("Input Methods", ".app"),
    ]
    /// The folder authorization plugins load from.
    static let authorizationPlugins = "/Library/Security/SecurityAgentPlugins"
    /// The folder OpenDirectory modules load from.
    static let directoryModules = "/Library/OpenDirectory/Modules"
    /// The daemon that keeps the authorization database. It's on the sealed system volume, so the path is its.
    static let authd = "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/"
        + "authd"
    /// The daemon that keeps the TCC databases, a platform binary signed as `com.apple.tccd` on the sealed system
    /// volume, so the path, the signature and the platform together are its.
    static let tccd = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
    /// The start of an environment entry that inserts dylibs.
    static let dyldInsert = "DYLD_INSERT_LIBRARIES="
    /// The daemon that saves preferences for `defaults` and apps. It's on the sealed system volume, so the path is its.
    static let cfprefsd = "/usr/sbin/cfprefsd"
    /// What a command line has when `defaults` imports a domain whole, for this host or every host.
    static let defaultsImport = ["defaults import", "-currentHost import"]
    /// What a command line has when it reads, exports or removes preferences rather than sets them: `defaults`,
    /// PlistBuddy's commands and plutil's options.
    static let preferenceReads = ["defaults read", "defaults export", "defaults delete", "Print :", "Delete :",
                                  "-remove ", "-extract ", "plutil -p"]
    /// An exec of launchctl, by its name or, for a copy with another name, its signature.
    static let launchctl = #"(event.exec.target.executable.name == "launchctl" "#
        + #"OR event.exec.target.signing_id == "com.apple.xpc.launchctl")"#
}

// MARK: - Collection
extension Indicator {
    /// The archives and disk images a modified close's file can be by its content (``FileTypeClassifier``): zip, xar
    /// (an installer package is one), gzip, bzip2, xz, 7-Zip, tar, Apple Archive, and a UDIF, raw, sparse or
    /// encrypted disk image or a sparse bundle's `Info.plist` (``DiskImage``). An `ar` archive is left out: its only
    /// type is `public.archive`, and what's written as one is a static library a build makes. So are the documents
    /// that are zip files (``ZipDocument``), which Launch Services doesn't count as archives.
    static let archiveTypes: [FileType] = [.zip, .xar, .gzip, .bzip2, .xz, .sevenZip, .tar, .appleArchive, .diskImage,
                                           .rawDiskImage, .sparseDiskImage, .sparseBundle, .encryptedDiskImage]
    /// The signing ID of backupd, Time Machine's daemon, a platform binary that copies files already on the Mac,
    /// archives and compiled scripts among them, to a backup.
    static let backupd = "com.apple.backupd"
    /// The signing IDs of macOS's own daemons whose work writes archives, or copies of what other processes wrote,
    /// all day on every Mac. Each is a platform binary and never adhoc signed, which a copy of it keeps and a
    /// lookalike doesn't:
    ///
    /// - backupd, Time Machine's (``backupd``).
    /// - fseventsd, which keeps each volume's file system event log, gzipped, in the `.fseventsd` folder at its root.
    /// - mds_stores, which keeps Spotlight's index of each volume in `.Spotlight-V100`, with a cache of the text it
    ///   indexes, so a script someone writes is written again there.
    /// - corespotlightd, which keeps each user's CoreSpotlight index, in `~/Library/Metadata/CoreSpotlight`, of what
    ///   apps give Spotlight, with the same index code, and so the same text cache, as mds_stores.
    /// - managedcorespotlightd, which keeps CoreSpotlight's managed index with the same index code as corespotlightd.
    ///   Its writes weren't recorded, so it's here by that code, as corespotlightd is.
    ///
    /// mdworker and mdworker_shared don't link the index code: they read files to index for mds, which links it but
    /// sends what to index to mds_stores, and wasn't recorded writing a file with content. With its code signing
    /// checks off (`amfi_get_out_of_my_way`), macOS makes every process a platform binary, so there a copy of one of
    /// these daemons is left out wherever it runs. An adhoc signed lookalike is still caught there: macOS reports its
    /// `CS_ADHOC` flag, which none of these daemons has.
    static let contentKeepers = [backupd, "com.apple.fseventsd", "com.apple.mds_stores", "com.apple.corespotlightd",
                                 "com.apple.managedcorespotlightd"]
    /// The signing IDs of macOS's disk image daemons, which write an attached image's blocks to its file:
    /// diskimagesiod, which runs as `_diskimagesiod` on macOS 27, and diskimages-helper, which macOS 27 still has.
    static let diskImageDaemons = ["com.apple.diskimagesiod", "com.apple.diskimages-helper"]
    /// Where a sparse bundle keeps its bands, Time Machine's on a network volume (a `.backupbundle`) among them. A band
    /// is a stretch of the disk's blocks, written all the time an image is attached, and can start with any file's
    /// first bytes, as a file system puts files at block boundaries: its type is the content's, not a write of it.
    static let bandFolders = ["*.sparsebundle/bands/*", "*.backupbundle/bands/*"]
    /// Where macOS keeps its system logs, which it rotates every night on every Mac, compressing the old ones
    /// (`system.log.0.gz`, `wifi.log.0.bz2`).
    static let systemLogFolder = "/private/var/log/*"
    /// The signing IDs of the programs that write macOS's rotated system logs: aslmanager, which gzips the logs it
    /// keeps itself (`system.log`, `install.log`), and bzip2 and gzip, which newsyslog runs for the logs it keeps
    /// (`wifi.log`). newsyslog doesn't write a compressed log itself. bzip2, bzcat and bunzip2 are one program, signed
    /// `com.apple.bzip2` on macOS 27.0 and `com.apple.bzcat` on macOS 27.2.
    static let logRotators = ["com.apple.aslmanager", "com.apple.bzip2", "com.apple.bzcat", "com.apple.gzip"]

    /// The comparisons a modified close passes when one of ``logRotators`` writes it in ``systemLogFolder``: a
    /// rotated log, once the process is macOS's own (``isApple``). The path comes first, as most archives are
    /// written elsewhere.
    ///
    /// Anything else writing an archive there still passes the rule, macOS's own zip, ditto, tar, `aa` and `cp` among
    /// them, as does a log rotator writing one anywhere else. An adhoc lookalike is caught even with the code signing
    /// checks off (`amfi_get_out_of_my_way`), where every process is a platform binary, by its `CS_ADHOC` flag.
    static let rotatedSystemLog = #"target_path LIKE[c] "\#(systemLogFolder)" AND "# + signedAs(logRotators)
}

// MARK: - Defense evasion
extension Indicator {
    /// The comparisons an exec's new code passes when it's adhoc signed: its `CS_ADHOC` flag, or its type, for a
    /// record without the flag. The seal an exec's label draws reads the same of the stored process.
    static let adhocTarget = "event.exec.target.is_adhoc_signed == YES "
        + #"OR event.exec.target.codesigning_type == "ADHOC""#
}

// MARK: - Command and control
extension Indicator {
    /// The system resolver's Unix domain socket, as Endpoint Security names it: mDNSResponder's, which launchd makes
    /// for it as root in `/private/var/run`. `getaddrinfo` and the rest of the BSD resolver connect to it.
    static let resolverSocket = "/private/var/run/mDNSResponder"
    /// The system resolver's XPC service, in the system domain: mDNSResponder's, which Network.framework, and so
    /// URLSession, connects to instead of its socket.
    static let resolverService = "com.apple.dnssd.service"
    /// The comparisons an initiating process passes when its code is adhoc signed or unsigned: its `CS_ADHOC` flag,
    /// or its type, `ADHOC` or `UNSIGNED`.
    ///
    /// Endpoint Security reports `CS_ADHOC` for adhoc code, linker-signed or signed with `codesign -s -`, both as the
    /// code a process execs and as a running process: on macOS 27.2 with SIP on, such a program is `ADHOC`, with no
    /// team ID, and not a platform binary. With the code signing checks off (`amfi_get_out_of_my_way`, as on the
    /// SIP-off test VM), macOS reports every process as a platform binary with no team ID, Developer ID apps among
    /// them, so the team ID and platform binary fields say nothing there. The rule reads only the flag, and the type
    /// Mac Monitor derives from the flags.
    ///
    /// Code signed with a certificate that has no team ID, such as a self-signed one, isn't adhoc and isn't matched.
    /// Signed code whose signature is no longer valid is: macOS clears `CS_VALID` when a process being debugged, or
    /// one without `CS_KILL` or `CS_HARD`, runs a page that doesn't match its signature, and Mac Monitor types such a
    /// process `UNSIGNED`.
    static let adhocOrUnsignedProcess = #"(process.is_adhoc_signed == YES "#
        + #"OR process.codesigning_type IN {"ADHOC", "UNSIGNED"})"#
}


// MARK: - Composing
extension Indicator {
    /// - Parameter types: Event types, without `ES_EVENT_TYPE_NOTIFY_`, that put a file in place.
    /// - Returns: The comparison a modified close, or an event of one of them, passes.
    static func written(or types: String...) -> String {
        "((" + type("CLOSE") + " AND event.close.modified == YES) OR " + type(types) + ")"
    }

    /// - Parameters:
    ///   - types: The types a file's content can be named by (``FileTypeClassifier``).
    ///   - others: What else macOS's own programs write all day, each the comparisons such a write passes besides
    ///     its process being macOS's own, as ``rotatedSystemLog`` is.
    /// - Returns: The comparisons a modified close of a file whose content is one of them passes, by anything but
    ///   macOS's own (``isApple``): one of ``contentKeepers``, one of ``diskImageDaemons`` writing a sparse bundle's
    ///   band (``bandFolders``), and the others. Only a modified close has a `file_type`, so the index looks the rule
    ///   up by the type, exactly, and the process and path are read only for those. What macOS's own programs share
    ///   is said once, after their signing IDs: most writers aren't one of them, and are told so by the ID alone.
    static func contentWritten(_ types: [FileType], besides others: [String] = []) -> String {
        let names = types.map { #""\#($0.identifier)""# }
        let writers = [signedAs(contentKeepers),
                       "(" + signedAs(diskImageDaemons) + " AND " + anyOf("target_path LIKE[c]", bandFolders) + ")"]
            + others.map { "(" + $0 + ")" }
        return type("CLOSE") + " AND event.close.modified == YES AND event.close.file_type "
            + (names.count == 1 ? "== " + names[0] : "IN {" + names.joined(separator: ", ") + "}")
            + " AND NOT ((" + writers.joined(separator: " OR ") + ") AND " + isApple + ")"
    }

    /// The comparisons a process passes when it's Apple's own program, whichever its signing ID says
    /// (``signedAs(_:)``): a platform binary and not adhoc signed, as a record without `is_adhoc_signed` reads.
    static let isApple = "process.is_platform_binary == YES AND process.is_adhoc_signed != YES"

    /// - Parameter signingIDs: Signing IDs.
    /// - Returns: The comparison a process signed as one of them passes.
    static func signedAs(_ signingIDs: [String]) -> String {
        "process.signing_id IN {" + signingIDs.map { #""\#($0)""# }.joined(separator: ", ") + "}"
    }

    /// - Parameters:
    ///   - comparison: A key path and an operator, as in `target_path ENDSWITH[c]`.
    ///   - values: The strings it compares with.
    /// - Returns: The comparison with each value, joined by `OR`, which a value passes when it passes any of them.
    ///   It has no parentheses of its own, for a list of alternatives that goes on.
    static func alternatives(_ comparison: String, _ values: [String]) -> String {
        values.map { #"\#(comparison) "\#($0)""# }.joined(separator: " OR ")
    }

    /// - Parameters:
    ///   - comparison: A key path and an operator, as in `target_path ENDSWITH[c]`.
    ///   - values: The strings it compares with.
    /// - Returns: The comparison with each value, joined by `OR` in parentheses, which a value passes when it passes
    ///   any of them.
    static func anyOf(_ comparison: String, _ values: [String]) -> String {
        "(" + alternatives(comparison, values) + ")"
    }

    /// - Parameter folder: A folder in a home folder's `Library`, as in `Scripts/Folder Action Scripts`.
    /// - Returns: The comparisons a path in it, or one that starts with its name, passes: in `/Users`, ignoring case,
    ///   and not in a `Library` deeper in the home folder, such as a container's or a backup's. They're joined by
    ///   `AND`, without parentheses of their own.
    static func homeLibraryPath(_ folder: String) -> String {
        #"target_path LIKE[c] "/Users/*/Library/\#(folder)*" AND NOT target_path LIKE[c] "/Users/*/*/Library/*""#
    }

    /// - Parameter folder: A folder in a home folder's `Library`, as in `Scripts/Folder Action Scripts`.
    /// - Returns: ``homeLibraryPath(_:)``'s comparisons, and not the `.DS_Store` Finder writes in a folder someone
    ///   opens: for a rule that takes any file in the folder.
    static func inHomeLibrary(_ folder: String) -> String {
        homeLibraryPath(folder) + #" AND NOT target_path ENDSWITH[c] "/.DS_Store""#
    }
}
