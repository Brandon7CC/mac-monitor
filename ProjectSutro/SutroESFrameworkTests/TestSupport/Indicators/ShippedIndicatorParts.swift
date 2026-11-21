//
//  ShippedIndicatorParts.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - What the shipped indicators' tests name
/// The programs and file types the tests of Mac Monitor's own indicators try them with. The predicates are the
/// linked pack's (``LinkedIndicatorPack``), written in the indicators repository: these are what the tests here
/// expect them to match and to leave out.
extension Indicator {
    /// The shipped indicators that are a rule on one event, in order: all but the sequences, which have steps in
    /// place of a predicate.
    static let eventDefaults = defaults.filter { $0.predicate != nil }
    /// tccd's path. It's on the sealed system volume, so the path is its.
    static let tccd = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
    /// Every archive type Archive written matches.
    static let archiveTypes: [FileType] = [.zip, .xar, .gzip, .bzip2, .xz, .sevenZip, .tar, .appleArchive, .diskImage,
                                           .rawDiskImage, .sparseDiskImage, .sparseBundle, .encryptedDiskImage]
    /// The signing ID of backupd, Time Machine's daemon, a platform binary that copies files already on the Mac,
    /// archives and compiled scripts among them, to a backup.
    static let backupd = "com.apple.backupd"
    /// The signing IDs of macOS's own daemons whose work writes archives, or copies of what other processes wrote,
    /// all day on every Mac: backupd, fseventsd, and Spotlight's mds_stores, corespotlightd and
    /// managedcorespotlightd. Archive written and AppleScript written leave each out as a platform binary.
    static let contentKeepers = [backupd, "com.apple.fseventsd", "com.apple.mds_stores", "com.apple.corespotlightd",
                                 "com.apple.managedcorespotlightd"]
    /// The signing IDs of the programs that write macOS's rotated system logs: aslmanager, bzip2 by both of its
    /// signing IDs, macOS 27.0's and 27.2's, and gzip. newsyslog runs bzip2 or gzip, and writes no archive.
    static let logRotators = ["com.apple.aslmanager", "com.apple.bzip2", "com.apple.bzcat", "com.apple.gzip"]
}
