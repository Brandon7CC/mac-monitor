//
//  StatusCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor status
/// Pins `macmonitor status`: how it's typed, what macOS's System Extension list says, and what it shows for a
/// Security Extension that's ready, lacks Full Disk Access, is older than `macmonitor`, or doesn't answer. `-v` is
/// pinned here too, as the short way to ask for the version.
final class StatusCommandTests: XCTestCase {
    /// `systemextensionsctl list` on the test VM, after several builds: old versions wait to be uninstalled, and one
    /// runs. Another vendor's extension is there too.
    private static let listing = """
        1 extension(s)
        --- com.apple.system_extension.endpoint_security (Go to 'System Settings > General > Login Items')
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        \t\t-\tcom.swiftlydetecting.agent.securityextension (3.1.0/66)\tMac Monitor Security Extension\t\
        [terminated waiting to uninstall on reboot]
        *\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent (8.10/213.02)\tFalcon Sensor\t[activated enabled]
        *\t*\t-\tcom.swiftlydetecting.agent.securityextension (3.1.0/97)\tMac Monitor Security Extension\t\
        [activated enabled]
        """

    /// A Security Extension's answer to a status request.
    ///
    /// - Parameters:
    ///   - endpointSecurity: What Endpoint Security answers it.
    ///   - app: Whether Mac Monitor is connected and recording.
    ///   - streams: How many `macmonitor` streams run.
    /// - Returns: The reply.
    private func reply(_ endpointSecurity: SensorReport.EndpointSecurity = .ok,
                       app: (connected: Bool, recording: Bool) = (true, true), streams: Int = 1) -> StreamReply {
        StreamReply(status: .ok, sensorVersion: "3.1.0 (97)",
                    report: SensorReport(endpointSecurity: endpointSecurity,
                                         app: SensorReport.App(connected: app.connected, recording: app.recording),
                                         streams: streams, streamCapacity: 3))
    }

    /// `status` takes `--json` and nothing else, and `-v` asks for the version as `--version` does.
    func testParsing() throws {
        XCTAssertEqual(try CommandLineParser.parse(["status"]), .status(StatusInvocation()))
        XCTAssertEqual(try CommandLineParser.parse(["status", "--json"]), .status(StatusInvocation(json: true)))
        XCTAssertEqual(try CommandLineParser.parse(["status", "-h"]), .help(command: "status"))
        XCTAssertThrowsError(try CommandLineParser.parse(["status", "now"]))
        XCTAssertThrowsError(try CommandLineParser.parse(["status", "--yaml"]))
        XCTAssertEqual(try CommandLineParser.parse(["-v"]), .version)
        XCTAssertEqual(try CommandLineParser.parse(["--version"]), .version)
        XCTAssertEqual(try CommandLineParser.parse(["version"]), .version)
        XCTAssertThrowsError(try CommandLineParser.parse(["-V"]))
        XCTAssertFalse(CommandLineCommand.status.requiresRoot)
    }

    /// The running version's state wins over versions waiting to be uninstalled, another vendor's extension is
    /// never read as Mac Monitor's, and a Mac with none listed has none.
    func testSystemExtensionStates() {
        XCTAssertEqual(SystemExtensionList.state(in: Self.listing), "activated enabled")
        let running = "(3.1.0/97)\tMac Monitor Security Extension\t"
        let waiting = Self.listing.replacingOccurrences(of: running + "[activated enabled]",
                                                        with: running + "[activated waiting for user]")
        XCTAssertEqual(SystemExtensionList.state(in: waiting), "activated waiting for user")
        let gone = Self.listing.split(separator: "\n").filter { !$0.contains("3.1.0/97") }.joined(separator: "\n")
        XCTAssertNil(SystemExtensionList.state(in: gone), "Only versions waiting to be uninstalled")
        XCTAssertNil(SystemExtensionList.state(in: ""))
        XCTAssertNil(SystemExtensionList.state(in: "0 extension(s)"))
    }

    /// A Security Extension that's activated and allowed a client is ready, and every fact is shown.
    func testAReadySecurityExtension() {
        let report = StatusReport(tool: "3.1.0 (97)", app: "3.1.0 (97)", systemExtension: "activated enabled",
                                  answer: .success(reply()))
        XCTAssertTrue(report.isReady)
        XCTAssertEqual(StatusCommand.output(report, json: false), """
            Versions
              macmonitor           3.1.0 (97)
              Mac Monitor          3.1.0 (97)
              Security Extension   3.1.0 (97)

            Security Extension
              Activated            yes
              Full Disk Access     granted

            Capturing
              Mac Monitor          connected, recording
              macmonitor streams   1 of 3

            """)
        let idle = StatusReport(tool: "3.1.0 (97)", app: nil, systemExtension: "activated enabled",
                                answer: .success(reply(app: (false, false), streams: 0)))
        let text = StatusCommand.output(idle, json: false)
        XCTAssertTrue(text.contains("  Mac Monitor          not found\n"))
        XCTAssertTrue(text.contains("  Mac Monitor          not connected\n"))
        XCTAssertTrue(text.contains("  macmonitor streams   0 of 3\n"))
        let stopped = StatusReport(tool: "1", app: "1", systemExtension: "activated enabled",
                                   answer: .success(reply(app: (true, false))))
        XCTAssertTrue(StatusCommand.output(stopped, json: false).contains("connected, not recording"))
    }

    /// Without Full Disk Access, or not activated, it isn't ready, and the text says what's missing.
    func testWhatItLacks() {
        let noAccess = StatusReport(tool: "1", app: "1", systemExtension: "activated enabled",
                                    answer: .success(reply(.notPermitted)))
        XCTAssertFalse(noAccess.isReady)
        XCTAssertEqual(noAccess.security_extension.full_disk_access, false)
        XCTAssertTrue(StatusCommand.output(noAccess, json: false).contains("Full Disk Access     missing: allow"))
        let waiting = StatusReport(tool: "1", app: "1", systemExtension: "activated waiting for user",
                                   answer: .failure(CommandLineFailure(.unavailable, "No Security Extension.")))
        XCTAssertFalse(waiting.isReady)
        let text = StatusCommand.output(waiting, json: false)
        XCTAssertTrue(text.contains("  Security Extension   no answer\n"))
        XCTAssertTrue(text.contains("  Activated            no (activated waiting for user)\n"))
        XCTAssertTrue(text.contains("  Full Disk Access     unknown\n"))
        XCTAssertTrue(text.contains("  Note                 No Security Extension.\n"))
        XCTAssertTrue(text.contains("  Mac Monitor          unknown\n"))
        let missing = StatusReport(tool: "1", app: nil, systemExtension: nil,
                                   answer: .failure(CommandLineFailure(.unavailable, "No Security Extension.")))
        let missingText = StatusCommand.output(missing, json: false)
        XCTAssertTrue(missingText.contains("  Activated            no (not installed)\n"))
    }

    /// A Security Extension older than 3.1.0 still says its version, and the note says why it says no more: it
    /// doesn't know the request, or only answers root.
    func testAnOlderSecurityExtension() {
        let unknown = StreamReply(status: .unsupported, problem: "Unknown kind.", sensorVersion: "3.0.0 (1)")
        let older = StatusReport(tool: "3.1.0 (97)", app: "3.1.0 (97)", systemExtension: "activated enabled",
                                 answer: .success(unknown))
        XCTAssertEqual(older.versions.security_extension, "3.0.0 (1)")
        XCTAssertFalse(older.isReady)
        XCTAssertEqual(older.security_extension.problem,
                       "The Security Extension is older than macmonitor and can't say. Open Mac Monitor to update it.")
        let refused = StreamReply(status: .refused, problem: "Needs root.", sensorVersion: "3.0.0 (1)")
        let rooted = StatusReport(tool: "3.1.0 (97)", app: nil, systemExtension: "activated enabled",
                                  answer: .success(refused))
        XCTAssertTrue(rooted.security_extension.problem?.contains("sudo macmonitor status") == true)
    }

    /// `--json` writes every part, with `null` for what isn't known.
    func testJSON() throws {
        let report = StatusReport(tool: "3.1.0 (97)", app: "3.1.0 (97)", systemExtension: "activated enabled",
                                  answer: .success(reply(app: (true, false), streams: 2)))
        let json = StatusCommand.output(report, json: true)
        XCTAssertTrue(json.hasSuffix("}\n"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: [String: Any]])
        XCTAssertEqual(Set(object.keys), ["versions", "security_extension", "capturing"])
        XCTAssertEqual(object["versions"]?["security_extension"] as? String, "3.1.0 (97)")
        XCTAssertEqual(object["security_extension"]?["activated"] as? Bool, true)
        XCTAssertEqual(object["security_extension"]?["full_disk_access"] as? Bool, true)
        XCTAssertEqual(object["security_extension"]?["endpoint_security"] as? String, "ok")
        XCTAssertEqual(object["capturing"]?["mac_monitor_recording"] as? Bool, false)
        XCTAssertEqual(object["capturing"]?["streams"] as? Int, 2)
        XCTAssertEqual(object["capturing"]?["stream_capacity"] as? Int, 3)
        let silent = StatusReport(tool: "3.1.0 (97)", app: nil, systemExtension: nil,
                                  answer: .failure(CommandLineFailure(.unavailable, "No answer.")))
        let unknown = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(StatusCommand.output(silent, json: true).utf8)) as? [String: [String: Any]])
        XCTAssertTrue(unknown["versions"]?["mac_monitor"] is NSNull)
        XCTAssertTrue(unknown["versions"]?["security_extension"] is NSNull)
        XCTAssertTrue(unknown["security_extension"]?["full_disk_access"] is NSNull)
        XCTAssertTrue(unknown["capturing"]?["streams"] is NSNull)
        XCTAssertEqual(unknown["security_extension"]?["problem"] as? String, "No answer.")
    }

    /// `--json` says Full Disk Access is unknown, as the text does, when Endpoint Security refuses a client for
    /// another reason, and says it's missing only when it's refused for Full Disk Access.
    func testJSONFullDiskAccessWhenEndpointSecurityRefuses() throws {
        let unknowns: [SensorReport.EndpointSecurity] = [.tooManyClients, .notEntitled, .failed]
        for endpointSecurity in unknowns {
            let report = StatusReport(tool: "3.1.0 (97)", app: "3.1.0 (97)", systemExtension: "activated enabled",
                                      answer: .success(reply(endpointSecurity)))
            XCTAssertNil(report.security_extension.full_disk_access, endpointSecurity.rawValue)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(
                with: Data(StatusCommand.output(report, json: true).utf8)) as? [String: [String: Any]])
            XCTAssertTrue(object["security_extension"]?["full_disk_access"] is NSNull, endpointSecurity.rawValue)
            XCTAssertEqual(object["security_extension"]?["endpoint_security"] as? String, endpointSecurity.rawValue)
            XCTAssertTrue(StatusCommand.output(report, json: false).contains("Full Disk Access     unknown: "),
                          endpointSecurity.rawValue)
        }
        let missing = StatusReport(tool: "3.1.0 (97)", app: "3.1.0 (97)", systemExtension: "activated enabled",
                                   answer: .success(reply(.notPermitted)))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(StatusCommand.output(missing, json: true).utf8)) as? [String: [String: Any]])
        XCTAssertEqual(object["security_extension"]?["full_disk_access"] as? Bool, false)
    }
}
