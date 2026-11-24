//
//  IndicatorPackSignature.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import Security


// MARK: - Indicator pack signature
/// A pack's detached CMS signature, verified over the payload (step 2 of ``IndicatorPackVerifier``): the signer's
/// certificate, and every certificate the signature carries to build its chain from.
///
/// Only the signature is checked here, with `CMSDecoder`. Who signed it is checked by ``IndicatorPackRequirement``
/// and ``IndicatorPackTrust``, so `CMSDecoderCopySignerStatus` is asked not to evaluate trust. Asked that way, it
/// reports `kCMSSignerValid` for a signature that verifies whatever anchor its chain ends at, and
/// `kCMSSignerInvalidSignature` for a changed payload. Asked to evaluate trust, a chain to an anchor this Mac doesn't
/// trust reports `kCMSSignerInvalidCert` with `CSSMERR_TP_NOT_TRUSTED`, and the anchors couldn't be the ones a test
/// injects.
///
/// `CMSDecoder` verifies a signature's own content when it has some, even after it's given the detached content, and
/// reports it valid. A signature that carries content is refused, so the payload is the only thing a signature can
/// be said to sign.
struct IndicatorPackSignature {
    /// The signer's certificate.
    let signer: SecCertificate
    /// Every certificate the signature carries, the signer's among them. Carrying one doesn't make it trusted: the
    /// certificates aren't signed.
    let certificates: [SecCertificate]
}

extension IndicatorPackSignature {
    /// Decode a signature and verify it over a payload: it must decode, carry no content of its own, have exactly
    /// one signer, and that signer's signature must verify over the payload's bytes.
    ///
    /// - Parameters:
    ///   - signature: The detached CMS signature, DER.
    ///   - payload: The bytes it must sign.
    /// - Throws: ``IndicatorPackError/unreadableSignature`` for one that doesn't decode,
    ///   ``IndicatorPackError/contentInSignature`` for one that carries content,
    ///   ``IndicatorPackError/signers(_:)`` for none or several signers, and
    ///   ``IndicatorPackError/signatureDoesNotVerify`` for one that doesn't verify over the payload.
    init(_ signature: Data, over payload: Data) throws(IndicatorPackError) {
        let decoder = try Self.decoder(for: signature, over: payload)

        var content: CFData?
        guard CMSDecoderCopyContent(decoder, &content) == errSecSuccess else { throw .unreadableSignature }
        guard content == nil else { throw .contentInSignature }

        var count = 0
        guard CMSDecoderGetNumSigners(decoder, &count) == errSecSuccess else { throw .unreadableSignature }
        guard count == 1 else { throw .signers(count) }

        var status = CMSSignerStatus.unsigned
        guard CMSDecoderCopySignerStatus(decoder, 0, SecPolicyCreateBasicX509(), false, &status, nil, nil)
                == errSecSuccess else { throw .unreadableSignature }
        guard status == .valid else { throw .signatureDoesNotVerify }

        var signer: SecCertificate?
        var certificates: CFArray?
        guard CMSDecoderCopySignerCert(decoder, 0, &signer) == errSecSuccess, let signer else {
            throw .unreadableSignature
        }
        CMSDecoderCopyAllCerts(decoder, &certificates)
        self.init(signer: signer, certificates: certificates as? [SecCertificate] ?? [])
    }

    /// A decoder that has read a whole signature and been given the payload as its detached content.
    ///
    /// `CMSDecoderFinalizeMessage` succeeds even after `CMSDecoderUpdateMessage` refused the bytes, so each call's
    /// result is checked.
    ///
    /// - Parameters:
    ///   - signature: The detached CMS signature, DER.
    ///   - payload: The bytes it must sign.
    /// - Returns: The decoder, finalized.
    /// - Throws: ``IndicatorPackError/unreadableSignature`` when a step fails.
    private static func decoder(for signature: Data, over payload: Data) throws(IndicatorPackError) -> CMSDecoder {
        var made: CMSDecoder?
        guard !signature.isEmpty, CMSDecoderCreate(&made) == errSecSuccess, let decoder = made else {
            throw .unreadableSignature
        }
        let read = signature.withUnsafeBytes { CMSDecoderUpdateMessage(decoder, $0.baseAddress!, $0.count) }
        guard read == errSecSuccess,
              CMSDecoderSetDetachedContent(decoder, payload as CFData) == errSecSuccess,
              CMSDecoderFinalizeMessage(decoder) == errSecSuccess else { throw .unreadableSignature }
        return decoder
    }
}
