//
//  IndicatorPackVerifyCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Verifying a pack
/// `macmonitor indicators pack verify FILE`: check a signed indicator pack as the Security Extension checks one before
/// installing it, without installing it. Its signature has to verify, its signer meet the Developer ID requirement
/// for Team ID 4HMJQ7V3SX with a certificate valid now and not revoked (``IndicatorPackVerifier``), and its payload be
/// a pack this build reads (``IndicatorPack/decode(_:)``). It says who signed it and what it holds:
///
/// ```text
/// Signed by “Developer ID Application: Brandon Dalton (4HMJQ7V3SX)”, Team ID 4HMJQ7V3SX.
/// Its certificate's SHA-256 is 3f2a…, and it expires on February 1, 2027.
/// Pack 1, built from commit f8911d2 on 2026-11-15T09:35:16Z, for Mac Monitor 3.2.0 or later.
/// 45 indicators, 2 of them sequences. 4 core identities and 3 retired.
/// ```
///
/// It needs neither root nor the Security Extension. It exits 0 for a pack Mac Monitor would install, 65 for one it
/// wouldn't, and 66 for a file that can't be read.
public enum IndicatorPackVerifyCommand {
    /// Verify a pack file and say what it holds.
    ///
    /// - Parameters:
    ///   - path: The signed pack file.
    ///   - output: Standard output.
    ///   - verifier: What checks the signature: a release's requirement unless given.
    /// - Returns: Success, or the exit status and why.
    public static func run(path: String, output: StreamOutput,
                           verifier: IndicatorPackVerifier = IndicatorPackVerifier())
        -> Result<Void, CommandLineFailure> {
        let file = TerminalSafeText.quoted(path)
        let data: Data
        do {
            data = try FileInput.read(path, upTo: IndicatorLimits.maxFileBytes)
        } catch {
            return .failure(CommandLineFailure(.noInput, "\(file) can't be read: \(error.localizedDescription)"))
        }
        let verified: VerifiedIndicatorPack
        do {
            verified = try verifier.verify(data, .installing)
        } catch {
            return .failure(CommandLineFailure(.dataError, "Mac Monitor wouldn't install \(file). \(error.message)"))
        }
        let pack: IndicatorPack
        do {
            pack = try IndicatorPack.decode(verified.payload)
        } catch {
            return .failure(CommandLineFailure(.dataError, "\(file) is signed, but its payload isn't a pack Mac "
                                                + "Monitor would install. \(error.description)"))
        }
        do {
            try output.write(Data(text(signer: verified.signer, pack: pack).utf8))
        } catch {
            return .failure(CommandLineFailure(.ioError, "What \(file) holds couldn't be written."))
        }
        return .success(())
    }

    /// What a verified pack holds, as `verify` says it.
    ///
    /// - Parameters:
    ///   - signer: Who signed it.
    ///   - pack: Its payload, read.
    /// - Returns: The lines, ending in a newline, every value escaped for a terminal.
    static func text(signer: IndicatorPackSigner, pack: IndicatorPack) -> String {
        let header = pack.pack
        let sequences = pack.indicators.filter { $0.sequence != nil }.count
        let kinds = sequences == 0 ? "" : ", \(sequences) of them \(sequences == 1 ? "a sequence" : "sequences")"
        let newer = pack.newer.isEmpty ? ""
            : " \(pack.newer.count) more \(pack.newer.count == 1 ? "needs" : "need") a newer Mac Monitor."
        return [
            "Signed by “\(signer.commonName)”, Team ID \(signer.teamID).",
            "Its certificate's SHA-256 is \(signer.certificateSHA256), and it expires on "
                + "\(IndicatorPackError.day(signer.expires)).",
            "Pack \(header.sequence), built from commit \(header.commit.prefix(7)) on \(header.published), for Mac "
                + "Monitor \(header.minEngine) or later.",
            "\(pack.indicators.count) \(pack.indicators.count == 1 ? "indicator" : "indicators")\(kinds). "
                + "\(header.core.count) core \(header.core.count == 1 ? "identity" : "identities") and "
                + "\(header.retired.count) retired.\(newer)",
        ].map(TerminalSafeText.text).joined(separator: "\n") + "\n"
    }
}
