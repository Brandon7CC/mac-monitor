//
//  IndicatorPackTrust.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import Security


// MARK: - Indicator pack trust
/// Whether the signer's chain is trusted (step 4 of ``IndicatorPackVerifier``), evaluated with SecTrust against the
/// system's anchors, or only the ones a test gives.
///
/// The chain is built from the signer's certificate and the ones the signature carries, under the basic X.509 policy
/// and a revocation policy, and how its dates count depends on the mode:
/// - ``IndicatorPackVerifier/Mode/installing``: valid now and not revoked. Revocation is checked by OCSP or CRL,
///   with the network, and soft-fails: a certificate reported revoked is refused, and one nobody answers for isn't.
///   trustd's cached answers and the revocation database it keeps for Apple's certificates count too.
/// - ``IndicatorPackVerifier/Mode/loading``: everything but the dates, without the network. A CMS signature has no
///   trusted timestamp, so expiry must never break a pack that was verified when it was installed. The chain is
///   evaluated now first, so a revocation trustd already knows of refuses it. Only when a certificate in the chain
///   isn't valid now is it evaluated again as of the signer's certificate's issue date, when every certificate that
///   issued it was valid. Then a revocation counts as far as trustd applies its answers to that date, and CAs stop
///   publishing a certificate's status once it expires anyway.
struct IndicatorPackTrust {
    /// The only anchors to trust, or `nil` for the system's.
    let anchors: [SecCertificate]?

    /// The chain SecTrust built, and why it isn't trusted, if it isn't.
    struct Evaluation {
        /// The chain, leaf first and anchor last. It's built even when it isn't trusted.
        let chain: [SecCertificate]
        /// Why the chain isn't trusted, or `nil` when it is.
        let failure: IndicatorPackError?
    }

    /// Evaluate a signer's chain.
    ///
    /// SecTrust's evaluation is synchronous, and installing may wait on the network for revocation, so call this off
    /// the main thread.
    ///
    /// - Parameters:
    ///   - signature: The verified signature, with the signer's certificate and the ones it carries.
    ///   - mode: Installing or loading, which decides how dates and revocation count.
    ///   - now: The time this Mac's clock says.
    /// - Returns: The chain and the failure, if any.
    func evaluate(_ signature: IndicatorPackSignature, _ mode: IndicatorPackVerifier.Mode,
                  at now: Date) -> Evaluation {
        let current = evaluate(signature, at: now, network: mode == .installing)
        guard current.failure != nil,
              let lapse = current.chain.lazy.compactMap(IndicatorPackCertificate.init)
                .compactMap({ $0.lapse(at: now) }).first else { return current }
        switch mode {
        case .installing, .checking:
            return Evaluation(chain: current.chain, failure: lapse)
        case .loading:
            guard let issued = IndicatorPackCertificate(signature.signer)?.notBefore else { return current }
            return evaluate(signature, at: issued, network: false)
        }
    }

    /// Evaluate a signer's chain once, at one time.
    ///
    /// - Parameters:
    ///   - signature: The verified signature.
    ///   - date: The time to evaluate it at.
    ///   - network: May trustd fetch revocation answers and missing certificates?
    /// - Returns: The chain and the failure, if any.
    private func evaluate(_ signature: IndicatorPackSignature, at date: Date, network: Bool) -> Evaluation {
        let revocation = kSecRevocationUseAnyAvailableMethod | (network ? 0 : kSecRevocationNetworkAccessDisabled)
        let policies = [SecPolicyCreateBasicX509()] + [SecPolicyCreateRevocation(revocation)].compactMap { $0 }
        var made: SecTrust?
        let certificates = [signature.signer] + signature.certificates
        guard SecTrustCreateWithCertificates(certificates as CFArray, policies as CFArray, &made) == errSecSuccess,
              let trust = made else {
            return Evaluation(chain: [signature.signer], failure: .untrusted(reason: "its chain can't be built"))
        }
        if let anchors {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }
        SecTrustSetVerifyDate(trust, date as CFDate)
        SecTrustSetNetworkFetchAllowed(trust, network)

        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust, &error)
        let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? [signature.signer]
        guard !trusted else { return Evaluation(chain: chain, failure: nil) }
        return Evaluation(chain: chain, failure: Self.failure(error))
    }

    /// What a SecTrust error means for a pack.
    ///
    /// - Parameter error: SecTrust's error.
    /// - Returns: ``IndicatorPackError/revoked`` for a revoked certificate, else
    ///   ``IndicatorPackError/untrusted(reason:)`` with SecTrust's reason.
    private static func failure(_ error: CFError?) -> IndicatorPackError {
        guard let error else { return .untrusted(reason: "SecTrust gave no reason") }
        if CFErrorGetCode(error) == Int(errSecCertificateRevoked) { return .revoked }
        return .untrusted(reason: CFErrorCopyDescription(error) as String? ?? "SecTrust gave no reason")
    }
}
