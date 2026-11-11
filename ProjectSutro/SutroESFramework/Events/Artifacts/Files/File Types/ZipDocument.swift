//
//  ZipDocument.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Documents that are zip files
/// The document formats stored as zip files, told apart from a zip archive by the entry their specifications put
/// first: an Office Open XML document's (`.docx`, `.xlsx`, `.pptx`) `[Content_Types].xml` or `_rels/.rels`, and an
/// OpenDocument's or EPUB's `mimetype`, stored uncompressed with the document's MIME type as its content. Launch
/// Services doesn't count any of them as an archive (`UTType.conforms(to: .archive)` is false), so saving one isn't
/// writing an archive.
///
/// Only the first local file header is read, from the bytes already sampled: a name at offset 30, its length at 26,
/// the extra field's length at 28 and the compression method at 8, all little-endian. A zip whose first entry is named
/// so is the document, whatever else it holds. A Java archive is still a zip: Launch Services counts it as one.
enum ZipDocument {
    /// A zip's local file header signature, which its first entry starts with.
    private static let localHeader = Array("PK\u{03}\u{04}".utf8)
    /// Where the first entry's name starts.
    private static let nameOffset = 30
    /// The first entries an Office Open XML package starts with: its content types, or its relationships.
    private static let openXMLNames = [Array("[Content_Types].xml".utf8), Array("_rels/.rels".utf8)]
    /// The entry an OpenDocument or EPUB starts with.
    private static let mimetypeName = Array("mimetype".utf8)
    /// The MIME types a `mimetype` entry starts with, and the document type each means.
    private static let mimeTypes: [(prefix: [UInt8], type: FileType)] = [
        (Array("application/vnd.oasis.opendocument.".utf8), .openDocument),
        (Array("application/epub+zip".utf8), .epub),
    ]

    /// Every type a zip's first entry can name.
    static let types: [FileType] = [.officeOpenXML] + mimeTypes.map(\.type)

    /// The document a zip is, by its first entry.
    ///
    /// - Parameter header: The file's first bytes, which start with a zip's local file header.
    /// - Returns: ``FileType/officeOpenXML``, ``FileType/openDocument`` or ``FileType/epub``, or `nil` for a zip
    ///   whose first entry names none, or one the bytes end before.
    static func type<Bytes: ByteSample>(of header: Bytes) -> FileType? {
        guard header.starts(with: localHeader), let nameLength = header.uint16(at: 26, bigEndian: false),
              let extraLength = header.uint16(at: 28, bigEndian: false) else { return nil }
        let name = header.dropFirst(nameOffset).prefix(Int(nameLength))
        guard name.count == Int(nameLength) else { return nil }
        if openXMLNames.contains(where: { name.elementsEqual($0) }) { return .officeOpenXML }
        /// A `mimetype` entry is stored: method 0.
        guard name.elementsEqual(mimetypeName), header.uint16(at: 8, bigEndian: false) == 0 else { return nil }
        let content = nameOffset + Int(nameLength) + Int(extraLength)
        return mimeTypes.first { header.has($0.prefix, at: content) }?.type
    }
}
