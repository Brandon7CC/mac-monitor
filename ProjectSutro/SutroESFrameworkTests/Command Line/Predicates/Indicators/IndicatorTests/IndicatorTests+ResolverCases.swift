//
//  IndicatorTests+ResolverCases.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Unsigned code resolved a name
/// The records Unsigned code resolved a name matches, and the ones close to them it doesn't, for ``defaultCases()``.
extension IndicatorTests {
    /// The initiating processes the cases name, by their signing fields as a record has them.
    private enum Signer {
        /// Adhoc as macOS reports it with its code signing checks off, as on the SIP-off test VM: `CS_ADHOC`, and a
        /// platform binary.
        case adhocChecksOff
        /// Adhoc as Endpoint Security reports it on macOS 27.2 with its checks on: `CS_ADHOC`, `ADHOC`, no team ID,
        /// and not a platform binary.
        case adhoc
        /// Typed `ADHOC` with `is_adhoc_signed` false, so the type alone decides.
        case adhocType
        /// Signed with a certificate that has no team ID, its team ID empty rather than none: not adhoc, not a
        /// platform binary, so `UNKNOWN`.
        case selfSignedEmptyTeam
        /// Unsigned: no valid signature, no signing ID and no team ID.
        case unsigned
        /// Developer ID signed code whose signature is no longer valid (`CS_VALID` cleared): `UNSIGNED`, its signing
        /// and team IDs kept.
        case invalidated
        /// Signed with a self-signed certificate: valid, not adhoc, not a platform binary, no team ID, so `UNKNOWN`.
        case selfSigned
        /// macOS's curl.
        case platform
        /// A Developer ID signed app.
        case developerID
        /// A Developer ID signed app as macOS reports it with its code signing checks off, as on the SIP-off test
        /// VM: a platform binary with no team ID, and not adhoc.
        case developerIDChecksOff

        /// The process's signing fields, as its record has them.
        var fields: [String: Any] {
            switch self {
            case .adhocChecksOff: Self.signer("PLATFORM", adhoc: true, platform: true, "resolve-adhoc", NSNull())
            case .adhoc: Self.signer("ADHOC", adhoc: true, platform: false, "resolve-adhoc", NSNull())
            case .adhocType: Self.signer("ADHOC", adhoc: false, platform: false, "resolve-adhoc", NSNull())
            case .selfSignedEmptyTeam: Self.signer("UNKNOWN", adhoc: false, platform: false, "com.example.local", "")
            case .unsigned: Self.signer("UNSIGNED", adhoc: false, platform: false, NSNull(), NSNull())
            case .invalidated:
                Self.signer("UNSIGNED", adhoc: false, platform: false, "com.example.app", "ABCDE12345")
            case .selfSigned: Self.signer("UNKNOWN", adhoc: false, platform: false, "com.example.local", NSNull())
            case .platform: Self.signer("PLATFORM", adhoc: false, platform: true, "com.apple.curl", NSNull())
            case .developerID:
                Self.signer("DEVELOPER_ID", adhoc: false, platform: false, "com.example.app", "ABCDE12345")
            case .developerIDChecksOff:
                Self.signer("PLATFORM", adhoc: false, platform: true, "com.example.app", NSNull())
            }
        }

        /// - Parameters:
        ///   - type: The code signing type.
        ///   - adhoc: Is `CS_ADHOC` set?
        ///   - platform: Is it a platform binary?
        ///   - signingID: Its signing ID, or `NSNull`.
        ///   - teamID: Its team ID, or `NSNull`.
        /// - Returns: The fields.
        private static func signer(_ type: String, adhoc: Bool, platform: Bool, _ signingID: Any,
                                   _ teamID: Any) -> [String: Any] {
            ["codesigning_type": type, "is_adhoc_signed": adhoc, "is_platform_binary": platform,
             "signing_id": signingID, "team_id": teamID]
        }
    }

    /// - Returns: Unsigned code resolved a name's cases: an adhoc or unsigned process connecting to the resolver's
    ///   root-owned socket at its exact path, or to its XPC service in the system domain, adhoc as macOS reports it
    ///   with its code signing checks on or off, typed `ADHOC`, or signed with a signature no longer valid (a
    ///   Developer ID app with `CS_VALID` cleared). A platform binary, a Developer ID app with the checks on or off,
    ///   self-signed code with no team ID, a socket named mDNSResponder elsewhere, one at the path that root doesn't
    ///   own, the service in a user's domain, another service, a bind and an open of the socket aren't.
    func resolverCases() -> [Case] {
        let name = "Unsigned code resolved a name"
        let socket = "/private/var/run/mDNSResponder"
        /// - Parameters:
        ///   - path: The socket's path.
        ///   - owner: The socket file's owner.
        ///   - signer: The process connecting.
        /// - Returns: A Unix domain socket connect's record.
        func connect(_ path: String = socket, owner: Int = 0, by signer: Signer) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT", "target_path": path,
             "event": ["uipc_connect": ["file": ["path": path, "stat": ["st_uid": owner]]]],
             "process": signer.fields]
        }
        /// - Parameters:
        ///   - service: The service's name.
        ///   - domain: Its domain's type and name.
        ///   - signer: The process connecting.
        /// - Returns: An XPC connect's record.
        func xpc(_ service: String = "com.apple.dnssd.service", domain: (Int, String) = (1, "SYSTEM"),
                 by signer: Signer) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT",
             "event": ["xpc_connect": ["service_name": service, "service_domain_type": domain.0,
                                       "service_domain_type_string": domain.1]],
             "process": signer.fields]
        }
        /// - Parameter type: The event type, without `ES_EVENT_TYPE_NOTIFY_`.
        /// - Returns: A record of an adhoc process's event at the socket's path.
        func other(_ type: String) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_\(type)", "target_path": socket, "process": Signer.adhoc.fields]
        }
        return [
            (name, connect(by: .adhocChecksOff), connect(by: .platform)),
            (name, connect(by: .adhoc), connect(by: .developerID)),
            (name, connect(by: .unsigned), connect("/private/tmp/x/mDNSResponder", by: .unsigned)),
            (name, connect(by: .adhocType), connect(owner: 501, by: .adhoc)),
            (name, connect(by: .adhoc), connect("/var/run/mDNSResponder", by: .adhoc)),
            (name, connect(by: .adhocChecksOff), connect(socket + ".old", by: .adhocChecksOff)),
            (name, connect(by: .adhoc), other("UIPC_BIND")),
            (name, connect(by: .unsigned), other("OPEN")),
            (name, xpc(by: .adhoc), xpc(domain: (2, "USER"), by: .adhoc)),
            (name, xpc(by: .adhocChecksOff), xpc("com.apple.system.opendirectoryd.libinfo", by: .adhocChecksOff)),
            (name, xpc(by: .unsigned), xpc(by: .platform)),
            (name, xpc(by: .adhocType), xpc(by: .developerID)),
            (name, connect(by: .invalidated), connect(by: .developerID)),
            (name, xpc(by: .invalidated), xpc(domain: (2, "USER"), by: .invalidated)),
            (name, connect(by: .adhoc), connect(by: .selfSigned)),
            (name, xpc(by: .adhoc), xpc(by: .selfSignedEmptyTeam)),
            (name, connect(by: .adhocChecksOff), connect(by: .developerIDChecksOff)),
            (name, xpc(by: .adhocChecksOff), xpc(by: .developerIDChecksOff)),
        ]
    }
}
