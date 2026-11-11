//
//  DiskImage.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Disk images
/// The disk images a file's sampled bytes name, each by exact bytes at a fixed offset in its first 4 KB or its last
/// 512, so none needs a read of its own (``FileTypeClassifier/headerLength``, ``FileTypeClassifier/trailerLength``):
///
/// - A UDIF image (`.dmg`, compressed or read-only) ends with its `koly` trailer. Its first bytes are its first
///   chunk's: raw, a gzip, bzip2 or xz stream, or other data.
/// - An encrypted image starts with `encrcdsa`. Its encryption wraps a UDIF, sparse or raw image alike, so its format
///   can't be told. An image of encryption's first version, which macOS 27's `hdiutil` doesn't write any more, ends
///   with `cdsaencr` instead, after data.
/// - A sparse image (`.sparseimage`) starts with `sprs`, and an Apple sparse image (`.asif`) with `shdw`.
/// - A raw image, as a read/write one (`UDRW`) is, starts with what the disk does. Only data is checked: these are
///   binary formats, so text with the same bytes stays text.
///   - A protective MBR's `0x55AA` at 510 and a GPT's `EFI PART` at 512.
///   - A FAT or exFAT boot sector, at 0 or after an MBR at 512, whose `0x55AA` is at its 510 and whose file system's
///     8-byte name is at a fixed place in it (`EXFAT   ` at 3, `FAT12   ` or `FAT16   ` at 54, `FAT32   ` at 82).
///   - An Apple Partition Map's driver descriptor (`ER` at 0) and first entry (`PM` at 512).
///   - With no partition map, an APFS container's superblock (`NXSB` at 32, with the object type of one at 24) or an
///     HFS+ volume's header (`H+` version 4 or `HX` version 5 at 1024).
/// - A sparse bundle (`.sparsebundle`) is a folder. Its `Info.plist`, and the `Info.bckup` copy of it, say what the
///   bundle is (`com.apple.diskimage.sparsebundle`), and they're named for the bundle they declare, as a zip's first
///   entry names the document, whether they're XML or binary property lists. Its `token` and `lock` are empty, and
///   its bands, in `bands`, are the disk's blocks, which can start with any file's first bytes, a raw disk's in the
///   first band: what reads a write leaves bands to their folder.
///
/// What else has these bytes: a disk or volume copied whole, as `dd` or a disk imaging tool writes one, which is a raw
/// image, and so is a virtual machine's raw disk, as Virtualization.framework's are, a Linux ISO with a GPT, a FAT
/// volume's image (a USB stick's, an EFI system partition's, a boot partition's), or a hybrid CD image with an Apple
/// Partition Map. A disk with 4 KB sectors has its GPT at 4,096, past the first 4 KB, so it isn't named. A disk with
/// only an MBR isn't either: `0x55AA` at 510 alone is two bytes that every MBR and boot sector has, so a boot sector
/// counts only with its file system's name, and an MBR only with the GPT or boot sector after it.
enum DiskImage {
    /// The signatures an image starts with, and the type each means: each is printable, so each counts only in bytes
    /// that aren't text.
    static let signatures: [(bytes: [UInt8], type: FileType)] = [
        (Array("encrcdsa".utf8), .encryptedDiskImage),
        (Array("sprs".utf8), .sparseDiskImage), (Array("shdw".utf8), .sparseDiskImage),
    ]
    /// The types whose files' end is read for a UDIF trailer: a UDIF image's first chunk, raw or compressed.
    static let trailerHeaders: Set<FileType> = [.data, .gzip, .bzip2, .xz, .rawDiskImage]

    /// A UDIF trailer's first bytes.
    private static let udifMagic = Array("koly".utf8)
    /// The last bytes of an image of encryption's first version, where its header is.
    private static let encryptedV1Magic = Array("cdsaencr".utf8)
    /// A boot sector's signature, at 510 from its start: a protective MBR's, an MBR's, or a FAT or exFAT volume's.
    private static let bootSignature = (bytes: [UInt8(0x55), 0xAA], offset: 510)
    /// A GPT's header, at 512, after its protective MBR.
    private static let partitionTable = (bytes: Array("EFI PART".utf8), offset: 512)
    /// Where a volume's boot sector can start: at the disk's start, or after an MBR, in its second sector.
    private static let bootSectorStarts = [0, 512]
    /// A FAT or exFAT boot sector's file system name, and where in the sector it is: exFAT's `FileSystemName`, FAT12
    /// and FAT16's `BS_FilSysType`, and FAT32's.
    private static let volumeNames: [(bytes: [UInt8], offset: Int)] = [
        (Array("EXFAT   ".utf8), 3), (Array("FAT12   ".utf8), 54), (Array("FAT16   ".utf8), 54),
        (Array("FAT32   ".utf8), 82),
    ]
    /// An Apple Partition Map's driver descriptor's signature (`sbSig`), at 0, and its first entry's (`pmSig`, then
    /// two reserved bytes), at 512.
    private static let appleMap = (descriptor: Array("ER".utf8), entry: Array("PM\0\0".utf8), entryOffset: 512)
    /// An APFS container superblock's magic, at 32 (`nx_magic`), after its object header.
    private static let containerMagic = (bytes: Array("NXSB".utf8), offset: 32)
    /// Where an object header's type is (`o_type`): a container superblock's low 16 bits are 1.
    private static let objectTypeOffset = 24
    /// An HFS+ volume header's signature and version, and an HFSX one's, at 1024.
    private static let volumeHeaders = (bytes: [Array("H+\0\u{04}".utf8), Array("HX\0\u{05}".utf8)], offset: 1_024)
    /// What a sparse bundle's `Info.plist` names its kind with: an XML property list holds it in a `<string>`, and a
    /// binary one holds it as is, as it does any ASCII string.
    private static let bundleMark = Array("com.apple.diskimage.sparsebundle".utf8)

    /// Is this data a raw disk's start?
    ///
    /// - Parameter data: A file's first bytes, which aren't text and start with no other signature.
    /// - Returns: ``FileType/rawDiskImage`` for a GPT, a FAT or exFAT boot sector, an Apple Partition Map, an APFS
    ///   container or an HFS+ volume, else `nil`.
    static func rawType<Bytes: ByteSample>(of data: Bytes) -> FileType? {
        if data.has(bootSignature.bytes, at: bootSignature.offset),
           data.has(partitionTable.bytes, at: partitionTable.offset)
            || bootSectorStarts.contains(where: { isBootSector(data, at: $0) }) {
            return .rawDiskImage
        }
        if data.has(appleMap.descriptor, at: 0), data.has(appleMap.entry, at: appleMap.entryOffset) {
            return .rawDiskImage
        }
        if data.has(containerMagic.bytes, at: containerMagic.offset),
           let type = data.uint32(at: objectTypeOffset, bigEndian: false), type & 0xFFFF == 1 {
            return .rawDiskImage
        }
        return volumeHeaders.bytes.contains { data.has($0, at: volumeHeaders.offset) } ? .rawDiskImage : nil
    }

    /// Is there a FAT or exFAT boot sector here: its `0x55AA`, and its file system's name?
    ///
    /// - Parameters:
    ///   - data: A file's first bytes.
    ///   - start: Where the sector starts in them.
    /// - Returns: Whether both are where the sector puts them.
    private static func isBootSector<Bytes: ByteSample>(_ data: Bytes, at start: Int) -> Bool {
        data.has(bootSignature.bytes, at: start + bootSignature.offset)
            && volumeNames.contains { data.has($0.bytes, at: start + $0.offset) }
    }

    /// Is this property list, XML or binary, a sparse bundle's `Info.plist`? One `memmem` over the sampled bytes,
    /// which only a property list's take.
    ///
    /// - Parameter plist: A file's first bytes, an XML or a binary property list's.
    /// - Returns: Whether they name the sparse bundle's kind.
    static func isSparseBundle<Bytes: ByteSample>(_ plist: Bytes) -> Bool {
        plist.holds(bundleMark)
    }

    /// A type from a file's first bytes, made an image's by its end.
    ///
    /// - Parameters:
    ///   - type: The type its first bytes gave, one of ``trailerHeaders``.
    ///   - trailer: The file's last 512 bytes.
    /// - Returns: ``FileType/diskImage`` for a `koly` trailer, ``FileType/encryptedDiskImage`` for data that ends
    ///   with `cdsaencr`, else `type`.
    static func type(_ type: FileType, trailer: [UInt8]) -> FileType {
        if trailer.starts(with: udifMagic) { return .diskImage }
        let isEncrypted = type == .data && trailer.suffix(encryptedV1Magic.count).elementsEqual(encryptedV1Magic)
        return isEncrypted ? .encryptedDiskImage : type
    }
}


// MARK: - Finding bytes
extension ByteSample {
    /// Do the bytes hold these anywhere? One `memmem` over contiguous bytes, which an array and its slices are.
    ///
    /// - Parameter needle: The bytes to look for.
    /// - Returns: Whether they're there in full.
    func holds(_ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty else { return true }
        let found = withContiguousStorageIfAvailable { haystack in
            needle.withUnsafeBytes { wanted in
                memmem(haystack.baseAddress, haystack.count, wanted.baseAddress, wanted.count) != nil
            }
        }
        return found ?? indices.contains { self[$0...].starts(with: needle) }
    }
}
