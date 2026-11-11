//
//  FileType.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - A file's type, by its content
/// What a file's first bytes say it is: a Launch Services type identifier, such as `com.apple.mach-o-dylib`, and for a
/// Mach-O its `MH_*` file type. Never what its name says: a `.txt` that's a Mach-O is a Mach-O.
///
/// Three values aren't type identifiers: ``empty`` for a file of 0 bytes, ``dyldSharedCache`` for a dyld shared cache
/// (which Launch Services has no identifier for), and ``replaced`` for a path that no longer names the file the event
/// did.
public struct FileType: Hashable, Sendable {
    /// A file of 0 bytes.
    public static let empty = "empty"
    /// A dyld shared cache: its first bytes are `dyld_v1`.
    public static let dyldSharedCache = "dyld_shared_cache"
    /// The path no longer names the file the event did: its device or inode differ, or a symbolic link is on the path
    /// now.
    public static let replaced = "replaced"

    /// The type identifier, or one of ``empty``, ``dyldSharedCache`` and ``replaced``.
    public let identifier: String
    /// The `MH_*` name of a Mach-O's `filetype`, such as `MH_DYLIB`, or `nil` when the content isn't Mach-O.
    public let machOType: String?

    /// - Parameters:
    ///   - identifier: The type identifier, or one of the special values.
    ///   - machOType: A Mach-O's `MH_*` file type.
    init(_ identifier: String, machOType: String? = nil) {
        (self.identifier, self.machOType) = (identifier, machOType)
    }

    /// Is this one of the values that isn't a Launch Services type identifier?
    ///
    /// - Parameter identifier: A `file_type`.
    /// - Returns: Whether it's ``empty``, ``dyldSharedCache`` or ``replaced``.
    public static func isSpecial(_ identifier: String) -> Bool {
        [empty, dyldSharedCache, replaced].contains(identifier)
    }
}


// MARK: - Type identifiers
/// The Launch Services type identifiers a ``FileTypeClassifier`` answers with, each declared on macOS 27
/// (`FileTypeIdentifierTests` checks every one with `UTType(_:)`).
extension FileType {
    static let data = FileType("public.data")
    static let plainText = FileType("public.plain-text")
    static let script = FileType("public.script")
    static let machOBinary = FileType("com.apple.mach-o-binary")
    /// No identifier is declared for an `ar` archive (a static library): `UTType(filenameExtension: "a")` is dynamic.
    /// So it's the type every archive conforms to.
    static let archive = FileType("public.archive")
    static let javaClass = FileType("com.sun.java-class")
    /// A compiled script, AppleScript or JXA: a `.scpt`'s type, which Launch Services names by its extension alone.
    static let compiledAppleScript = FileType("com.apple.applescript.script")
    /// Text AppleScript, which a script is by its content only when its `#!` line names osascript
    /// (``ShebangLine/identifiers``): text AppleScript without one is ``plainText``.
    static let appleScriptText = FileType("com.apple.applescript.text")
    static let zip = FileType("public.zip-archive")
    /// An Office Open XML document, such as a `.docx`: a zip that isn't an archive (``ZipDocument``).
    static let officeOpenXML = FileType("org.openxmlformats.openxml")
    /// An OpenDocument, such as an `.odt`: a zip that isn't an archive.
    static let openDocument = FileType("org.oasis-open.opendocument")
    /// An EPUB publication: a zip that isn't an archive.
    static let epub = FileType("org.idpf.epub-container")
    static let xar = FileType("com.apple.xar-archive")
    static let gzip = FileType("org.gnu.gnu-zip-archive")
    static let bzip2 = FileType("public.bzip2-archive")
    static let xz = FileType("org.tukaani.xz-archive")
    static let sevenZip = FileType("org.7-zip.7-zip-archive")
    static let tar = FileType("public.tar-archive")
    static let appleArchive = FileType("com.apple.archive")
    /// A UDIF image, by its `koly` trailer: a compressed or read-only `.dmg` (``DiskImage``).
    static let diskImage = FileType("com.apple.disk-image-udif")
    /// A raw image, a read/write `.dmg`'s format: a disk's blocks as they are, from a GPT, an APFS container or an
    /// HFS+ volume. Launch Services declares the identifier, with no extension.
    static let rawDiskImage = FileType("com.apple.disk-image-raw")
    /// A sparse image: a `.sparseimage`, or an Apple sparse image, an `.asif`, which Launch Services names alike.
    static let sparseDiskImage = FileType("com.apple.disk-image-sparse")
    /// A sparse bundle's `Info.plist`, which makes a folder one: named for the bundle, a `.sparsebundle`.
    static let sparseBundle = FileType("com.apple.disk-image-sparse-bundle")
    /// An encrypted image, whose encryption hides its format. No identifier is declared for one, so it's the type
    /// every disk image conforms to.
    static let encryptedDiskImage = FileType("com.apple.disk-image")
    static let elf = FileType("public.elf-binary")
    static let windowsExecutable = FileType("com.microsoft.windows-executable")
    static let binaryPropertyList = FileType("com.apple.binary-property-list")
    static let xmlPropertyList = FileType("com.apple.xml-property-list")
    static let pdf = FileType("com.adobe.pdf")
    static let dyldCache = FileType(dyldSharedCache)
    static let emptyFile = FileType(empty)
    static let replacedFile = FileType(replaced)

    /// Every type identifier a ``FileTypeClassifier`` answers with by itself: all but Mach-O's by file type
    /// (``MachOHeader/identifiers``), scripts' by interpreter (``ShebangLine/identifiers``) and the special values.
    /// A test holds the classifier's signatures to it, and what reads a `file_type`, such as Archive written's
    /// archives, is decided against it, so a type the classifier learns goes here.
    static let classified: [FileType] = [
        .data, .plainText, .script, .machOBinary, .archive, .javaClass, .compiledAppleScript, .zip, .officeOpenXML,
        .openDocument, .epub, .xar, .gzip, .bzip2, .xz, .sevenZip, .tar, .appleArchive, .diskImage, .rawDiskImage,
        .sparseDiskImage, .sparseBundle, .encryptedDiskImage, .elf, .windowsExecutable, .binaryPropertyList,
        .xmlPropertyList, .pdf,
    ]
}
