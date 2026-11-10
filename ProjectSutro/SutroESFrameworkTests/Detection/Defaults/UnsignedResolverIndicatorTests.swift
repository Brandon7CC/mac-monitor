//
//  UnsignedResolverIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Unsigned code resolved a name
/// Pins Unsigned code resolved a name on the events `macmonitor stream` recorded on the SIP-off macOS 27 test VM
/// (`Fixtures/macmonitor-3.1-resolver.jsonl`): curl and Apple's python3 connecting to mDNSResponder's socket, then an
/// adhoc, linker-signed program that resolves a name with `getaddrinfo` connecting to Open Directory's XPC service and
/// to the socket. The Security Extension's compiled set and Mac Monitor's own matching agree on each of them, and on
/// each derived from them by changing only what the rule reads: the process's signing, the socket's path or owner,
/// or the XPC service. A hit is stamped as a shipped low indicator, and the rule is looked up by the socket's exact
/// path or the service's exact name, so no other connect is evaluated against it.
final class UnsignedResolverIndicatorTests: XCTestCase {
    /// The indicator's name.
    private static let name = "Unsigned code resolved a name"
    /// The fixture's events, in the order they ran.
    private static let fixture = "macmonitor-3.1-resolver.jsonl"
    /// The code signing flags Endpoint Security reports on macOS 27.2, with its checks on, for a running adhoc,
    /// linker-signed program: `CS_VALID`, `CS_ADHOC`, `CS_KILL`, `CS_LINKER_SIGNED`, `CS_NO_UNTRUSTED_HELPERS` and
    /// `CS_SIGNED`.
    private static let adhocFlags: Int64 = 0x2202_0203
    /// A program's, signed with a certificate that has no team ID: `CS_VALID`, `CS_KILL`, `CS_NO_UNTRUSTED_HELPERS`
    /// and `CS_SIGNED`, without `CS_ADHOC`.
    private static let noTeamFlags: Int64 = 0x2200_0201
    /// macOS's own code's, as `/usr/bin/true` is reported: a platform binary's, without `CS_ADHOC`.
    private static let platformFlags: Int64 = 0x2601_1B11
    /// A Developer ID app's: `CS_VALID`, `CS_HARD`, `CS_KILL`, `CS_RUNTIME`, `CS_NO_UNTRUSTED_HELPERS` and
    /// `CS_SIGNED`.
    private static let developerIDFlags: Int64 = 0x2201_0301
    /// `CS_PLATFORM_BINARY`, which macOS sets on every process with its code signing checks off.
    private static let platformBinaryFlag: Int64 = 0x0400_0000

    /// Only the adhoc program's socket connect matches: not curl's nor python3's, which are platform binaries, nor the
    /// adhoc program's connect to another XPC service. The extension and the app agree on each.
    func testRecordedConnectsMatch() throws {
        let messages = try fixtureMessages(Self.fixture)
        XCTAssertEqual(messages.map(\.es_event_type), ["ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT",
                                                       "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT",
                                                       "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT",
                                                       "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT"])
        XCTAssertEqual(try messages.map { try matches($0) }, [false, false, false, true])
    }

    /// Each process the rule is about, from the recorded adhoc connect with only its signing changed: adhoc as
    /// Endpoint Security reports it with its checks on, `CS_ADHOC` and not a platform binary, and unsigned, match. A
    /// Developer ID app doesn't, whether reported with the checks on or, as a platform binary with no team ID, off.
    /// Nor does code signed with a certificate that has no team ID, which isn't adhoc, or a platform binary without
    /// `CS_ADHOC`, as macOS's own code is.
    func testSigningDecides() throws {
        let adhoc = try recorded(3)
        XCTAssertTrue(try matches(adhoc), "adhoc with the checks off")
        XCTAssertTrue(try matches(signed(adhoc, flags: Self.adhocFlags)), "adhoc with the checks on")
        XCTAssertFalse(try matches(signed(adhoc, flags: Self.noTeamFlags, signingID: "com.example.local")), "no team")
        XCTAssertTrue(try matches(signed(adhoc, flags: 0, signingID: nil)), "unsigned")
        XCTAssertFalse(try matches(signed(adhoc, flags: Self.developerIDFlags, signingID: "com.example.resolver",
                                          teamID: "ABCDE12345", type: .developerId)), "Developer ID")
        XCTAssertFalse(try matches(signed(adhoc, flags: Self.developerIDFlags | Self.platformBinaryFlag,
                                          signingID: "com.example.resolver", platform: true)),
                       "Developer ID with the checks off")
        XCTAssertFalse(try matches(signed(adhoc, flags: Self.platformFlags, signingID: "com.apple.curl",
                                          platform: true)), "a platform binary, as macOS's own code is")
    }

    /// The socket has to be the resolver's: a socket named mDNSResponder anywhere else doesn't match, nor one at its
    /// path that root doesn't own.
    func testSocketIsTheResolversOwn() throws {
        let adhoc = try recorded(3)
        for path in ["/private/tmp/x/mDNSResponder", "/var/run/mDNSResponder", "/private/var/run/mDNSResponder2"] {
            XCTAssertFalse(try matches(socket(adhoc) { $0.path = path }), path)
        }
        XCTAssertFalse(try matches(socket(adhoc) { $0.stat.st_uid = 501 }), "owned by 501")
        XCTAssertTrue(try matches(socket(adhoc) { $0.stat.st_gid = 20 }), "root's, in another group")
    }

    /// The resolver's XPC service matches only in the system domain, and another service doesn't.
    func testXPCServiceInTheSystemDomain() throws {
        let other = try recorded(2)
        XCTAssertFalse(try matches(other), "Open Directory's service")
        let resolver = service(other) { $0.service_name = "com.apple.dnssd.service" }
        XCTAssertTrue(try matches(resolver), "the resolver's")
        XCTAssertTrue(try matches(signed(resolver, flags: Self.adhocFlags)), "the resolver's, adhoc with checks on")
        XCTAssertFalse(try matches(service(resolver) { $0.service_domain_type = 2 }), "a user's domain")
        XCTAssertFalse(try matches(service(resolver) { $0.service_name = "com.apple.dnssd.service.x" }), "a suffix")
    }

    /// A match is stamped as the Security Extension stamps it: the indicator's name, low, Command and Control's
    /// T1071.004, shipped and unedited, and the verdict survives the wire.
    func testHitIsStampedAsShippedLow() throws {
        let id = try shippedID(Self.name)
        XCTAssertEqual(id, Indicator.uuid(60))
        var message = try recorded(3)
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let hit = try XCTUnwrap(message.indicators?.hits.first { $0.id == id })
        XCTAssertEqual(hit.name, Self.name)
        XCTAssertEqual(hit.severity, .low)
        XCTAssertEqual(hit.tactic_id, "TA0011")
        XCTAssertEqual(hit.technique, "T1071.004")
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(hit.edited)
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators)
    }

    /// The rule runs on Unix domain socket and XPC connects only, and the index evaluates it only on a connect to the
    /// resolver's exact socket path or service name, so every other connect costs it one lookup.
    func testRuleIsAnchoredOnTheResolver() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == Self.name })
        let rule = try IndicatorCompiler.compile(indicator.predicate).get()
        let uipc = Int(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT.rawValue), xpc = Int(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT.rawValue)
        XCTAssertEqual(Set(rule.types), [uipc, xpc])
        let anchors = [uipc, xpc].map { type -> [String] in
            guard case .anyOf(let anchors) = rule.program.necessity(eventType: type) else { return ["unanchored"] }
            return anchors.map { anchor in
                let bytes = rule.program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
                return "\(anchor.field) \(anchor.shape) \(String(decoding: bytes, as: UTF8.self))"
            }
        }
        XCTAssertEqual(anchors, [["targetPath exact /private/var/run/mDNSResponder"],
                                 ["xpcConnectServiceName exact com.apple.dnssd.service"]])
    }
}


// MARK: - Deriving events
extension UnsignedResolverIndicatorTests {
    /// Does the shipped set match an event? The extension's compiled set and the app's matching have to agree, with
    /// every indicator decided.
    ///
    /// - Parameter message: The event.
    /// - Returns: Whether Unsigned code resolved a name is among its hits.
    /// - Throws: The error storing the event, or a failure when the extension and the app disagree.
    private func matches(_ message: Message, file: StaticString = #filePath, line: UInt = #line) throws -> Bool {
        let id = try shippedID(Self.name)
        var values = MessageValueCache()
        let evaluation = Self.shippedIndicators.evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined, [], message.context ?? "", file: file, line: line)
        XCTAssertEqual(evaluation.hits.map(\.id), try matcherHits(message), message.context ?? "",
                       file: file, line: line)
        return evaluation.hits.contains { $0.id == id }
    }

    /// - Parameter index: The event's place in the fixture.
    /// - Returns: The recorded event.
    /// - Throws: The error reading the fixture.
    private func recorded(_ index: Int) throws -> Message {
        try fixtureMessages(Self.fixture)[index]
    }

    /// An event with its process's signing changed, and what Mac Monitor derives from it derived again, as the
    /// Security Extension derives it from what Endpoint Security reports.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - flags: The process's code signing flags.
    ///   - signingID: Its signing ID.
    ///   - teamID: Its team ID.
    ///   - platform: Is it a platform binary?
    ///   - type: The type its certificates give, where its flags don't tell.
    /// - Returns: The event.
    private func signed(_ message: Message, flags: Int64, signingID: String? = "resolve-adhoc",
                        teamID: String? = nil, platform: Bool = false,
                        type: CodeSigningType = .unknown) -> Message {
        var message = message
        message.process.codesigning_flags = flags
        message.process.signing_id = signingID
        message.process.team_id = teamID
        message.process.is_platform_binary = platform
        message.process.codesigning_type = type
        message.process.enrich()
        return message
    }

    /// - Parameters:
    ///   - message: A Unix domain socket connect.
    ///   - change: The change to its socket's file.
    /// - Returns: The connect with its socket changed, and its target path the socket's.
    private func socket(_ message: Message, _ change: (inout File) -> Void) -> Message {
        guard case .uipc_connect(var connect) = message.event else {
            XCTFail("Not a Unix domain socket connect")
            return message
        }
        var message = message
        change(&connect.file)
        message.event = .uipc_connect(connect)
        message.target_path = connect.file.path
        return message
    }

    /// - Parameters:
    ///   - message: An XPC connect.
    ///   - change: The change to it, after which its domain's name is derived again.
    /// - Returns: The connect changed.
    private func service(_ message: Message, _ change: (inout XPCConnectEvent) -> Void) -> Message {
        guard case .xpc_connect(var connect) = message.event else {
            XCTFail("Not an XPC connect")
            return message
        }
        var message = message
        change(&connect)
        connect.enrich()
        message.event = .xpc_connect(connect)
        return message
    }
}
