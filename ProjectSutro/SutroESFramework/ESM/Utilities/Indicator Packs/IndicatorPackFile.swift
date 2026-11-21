//
//  IndicatorPackFile.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Indicator pack file
/// A signed indicator pack as a release ships it, taken apart (step 1 of ``IndicatorPackVerifier``). The indicators
/// repository's `tools/mmilib/pack.py` writes it (`PackBuilder.wrapped`): JSON carrying the pack's payload and a
/// detached CMS signature over exactly the payload's bytes, both in base64.
///
/// ```json
/// { "format": "com.swiftlydetecting.indicator-pack", "version": 1, "payload": "...", "signature": "..." }
/// ```
///
/// Reading a file checks only its shape. Nothing in it is trusted until ``IndicatorPackVerifier`` checks the
/// signature.
public struct IndicatorPackFile: Equatable {
    /// What a signed pack says it is.
    public static let format = "com.swiftlydetecting.indicator-pack"
    /// The version this build reads.
    public static let currentVersion = 1

    /// The payload's bytes: the pack, as signed.
    public let payload: Data
    /// The detached CMS signature over ``payload``, DER.
    public let signature: Data

    /// The file's JSON. The payload and signature are optional so a file of another format or version is refused
    /// for that, whatever else it has.
    private struct Contents: Decodable {
        /// What the file says it is.
        let format: String
        /// The file's version.
        let version: Int
        /// The payload, in base64.
        let payload: String?
        /// The signature, in base64.
        let signature: String?
    }

    /// Read a pack file: at most ``IndicatorLimits/maxFileBytes``, JSON, this format and version, and a base64
    /// payload and signature.
    ///
    /// - Parameter data: The file's bytes.
    /// - Throws: ``IndicatorPackError/tooLarge(bytes:)`` before parsing a file that's too large,
    ///   ``IndicatorPackError/unreadable`` for one that isn't JSON or has no payload or a payload or signature that
    ///   isn't base64, ``IndicatorPackError/unknownFormat(_:)`` and ``IndicatorPackError/unsupportedVersion(_:)``
    ///   for another format or version, and ``IndicatorPackError/unsigned`` for one without a signature, or an empty
    ///   one.
    public init(_ data: Data) throws(IndicatorPackError) {
        guard data.count <= IndicatorLimits.maxFileBytes else { throw .tooLarge(bytes: data.count) }
        guard let contents = try? JSONDecoder().decode(Contents.self, from: data) else { throw .unreadable }
        /// Only the start of what it says it is: the file isn't trusted, and the error is told to the user.
        guard contents.format == Self.format else { throw .unknownFormat(String(contents.format.prefix(64))) }
        guard contents.version == Self.currentVersion else { throw .unsupportedVersion(contents.version) }
        guard let encoded = contents.payload, let payload = Data(base64Encoded: encoded), !payload.isEmpty else {
            throw .unreadable
        }
        guard let encodedSignature = contents.signature, !encodedSignature.isEmpty else { throw .unsigned }
        guard let signature = Data(base64Encoded: encodedSignature) else { throw .unreadable }
        self.payload = payload
        self.signature = signature
    }
}


// MARK: - The installed pack
extension IndicatorPackFile {
    /// The installed pack as the Security Extension keeps it (Security Extension context): `indicator-pack.json`
    /// beside `indicators.json` in ``RootFileStore/systemDirectory``, `root:wheel` and 0600. It's the file exactly as
    /// it was signed, so its signature is checked again each time it's loaded.
    public static let installedLayout = RootFileStore.Layout(fileName: "indicator-pack.json",
                                                             unreadableFileName: "indicator-pack.unreadable.json",
                                                             temporaryPrefix: ".indicator-pack.",
                                                             maxBytes: IndicatorLimits.maxFileBytes,
                                                             noun: "indicator pack")
    /// The marker kept while the installed pack is read and its indicators are compiled (``SavedIndicatorSet``): one
    /// found at startup means the last try stopped the Security Extension.
    public static let loadingLayout = RootFileStore.Layout(fileName: "indicator-pack.loading",
                                                           unreadableFileName: "indicator-pack.loading.unreadable",
                                                           temporaryPrefix: ".indicator-pack.loading.", maxBytes: 0,
                                                           noun: "indicator pack loading marker")
}
