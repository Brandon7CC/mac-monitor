//
//  IndicatorPackVerifier.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import Security


// MARK: - Indicator pack verifier
/// Decides whether a signed indicator pack, such as one downloaded from a GitHub release, can be trusted, and returns
/// its payload's bytes and who signed them (Security Extension and `macmonitor` context). Fetching, installing and
/// decoding the payload are the caller's.
///
/// A pack is accepted only when, in this order:
/// 1. The file is at most ``IndicatorLimits/maxFileBytes``, its JSON reads, and its format and version are ones this
///    build reads (``IndicatorPackFile``)
/// 2. Its detached CMS signature has exactly one signer, carries no content of its own, and verifies over exactly
///    the payload's bytes (``IndicatorPackSignature``)
/// 3. The signer's chain meets the requirement: a Developer ID Application certificate of ``SensorXPC/teamID``
///    (``IndicatorPackRequirement``)
/// 4. The chain is trusted, as the mode decides: valid now and not revoked when installing, everything but the dates
///    when loading (``IndicatorPackTrust``)
///
/// The indicators repository signs a pack with its `tools/sign`. A test's anchors and requirement are injected
/// (``init(requirement:anchors:clock:)``).
public struct IndicatorPackVerifier {
    /// When a pack is verified, which decides how its certificate's dates and revocation count.
    public enum Mode: Sendable {
        /// Before it's installed: the certificate must be valid now and not revoked, asking the network.
        case installing
        /// To say what installing it would do, for a caller that may not install it: the certificate must be valid
        /// now, and a revocation counts as far as this Mac already knows of it. The network isn't asked, so a caller
        /// that may only read can't have the Security Extension fetch what a pack's certificates name.
        case checking
        /// When the Security Extension loads an installed pack at startup. It was verified when it was installed and
        /// is kept root-only, so everything is checked except the dates, and nothing waits on the network.
        case loading
    }

    /// Who must have signed the pack.
    public let requirement: IndicatorPackRequirement
    /// The only anchors to trust, or `nil` for the system's.
    public let anchors: [SecCertificate]?
    /// What time it is.
    private let clock: () -> Date

    /// - Parameters:
    ///   - requirement: Who must have signed the pack: Swiftly Detecting's Developer ID Application certificate, or
    ///     a test's.
    ///   - anchors: The only anchors to trust, or `nil` for the system's. Tests pass their own root.
    ///   - clock: What time it is. Tests pass one.
    public init(requirement: IndicatorPackRequirement = .developerID, anchors: [SecCertificate]? = nil,
                clock: @escaping () -> Date = Date.init) {
        self.requirement = requirement
        self.anchors = anchors
        self.clock = clock
    }

    /// Verify a pack file.
    ///
    /// SecTrust's evaluation is synchronous, and installing may wait on the network for revocation, so call this off
    /// the main thread.
    ///
    /// - Parameters:
    ///   - file: The pack file's bytes.
    ///   - mode: Installing or loading.
    /// - Returns: The payload's bytes, exactly as signed, and the signer.
    /// - Throws: The first step's ``IndicatorPackError``: the file's (``IndicatorPackFile/init(_:)``), then the
    ///   signature's, then the requirement's, then the chain's trust.
    public func verify(_ file: Data, _ mode: Mode) throws(IndicatorPackError) -> VerifiedIndicatorPack {
        let pack = try IndicatorPackFile(file)
        let signature = try IndicatorPackSignature(pack.signature, over: pack.payload)
        let trust = IndicatorPackTrust(anchors: anchors).evaluate(signature, mode, at: clock())
        try requirement.check(trust.chain)
        if let failure = trust.failure { throw failure }
        guard let signer = IndicatorPackCertificate(signature.signer) else { throw .unreadableSignature }
        return VerifiedIndicatorPack(payload: pack.payload, signer: IndicatorPackSigner(signer))
    }
}
