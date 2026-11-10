//
//  IndicatorBenchmarkEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Events and rules the indicator benchmarks evaluate
extension XCTestCase {
    /// The event types the evaluation benchmarks time, as their names have them.
    static let indicatorBenchmarkTypes: [(name: String, type: es_event_type_t)] = [
        ("exec", ES_EVENT_TYPE_NOTIFY_EXEC), ("close", ES_EVENT_TYPE_NOTIFY_CLOSE),
        ("create", ES_EVENT_TYPE_NOTIFY_CREATE), ("open", ES_EVENT_TYPE_NOTIFY_OPEN),
    ]

    /// A recording's events of one type (``recordingEvents(_:)``), with the benchmark exec among the execs, each with
    /// native strings, as a capture lane builds them (``nativeCopy(of:)``).
    ///
    /// - Parameters:
    ///   - type: The type.
    ///   - count: How many.
    /// - Returns: The events, in turn.
    /// - Throws: The error making them.
    func indicatorEvents(_ type: es_event_type_t, count: Int) throws -> [Message] {
        let name = eventTypeToString(from: type)
        var kinds = try recordingEvents(400).filter { $0.es_event_type == name }
        if type == ES_EVENT_TYPE_NOTIFY_EXEC { kinds.append(try benchmarkExec()) }
        guard !kinds.isEmpty else { throw BenchmarkFailure("No \(name) events") }
        kinds = try kinds.map(nativeCopy)
        return (0..<count).map { kinds[$0 % kinds.count] }
    }

    /// An event with every string native UTF-8, as a capture lane builds it from Endpoint Security's message. One read
    /// from a trace has the strings `JSONSerialization` bridged from Foundation, which string matching copies before
    /// it reads them. The wire's coding makes each one native.
    ///
    /// - Parameter message: The event.
    /// - Returns: The same event.
    /// - Throws: The error encoding or decoding it.
    func nativeCopy(of message: Message) throws -> Message {
        try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message))
    }

    /// Many distinct rules from the shipped ones: each shipped rule, cycled, with a check that never fails added at
    /// its end, so none shares another's program and each is as costly as the one it copies.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - type: Only the shipped rules that run on this type, or every one.
    /// - Returns: The rules.
    /// - Throws: A failure when no shipped rule runs on the type.
    func distinctRules(_ count: Int, for type: es_event_type_t? = nil) throws -> [Indicator] {
        let shipped = Indicator.defaults.filter { indicator in
            guard let type, case .success(let rule) = IndicatorCompiler.compile(indicator.predicate) else {
                return type == nil
            }
            return rule.types.contains(Int(type.rawValue))
        }
        guard !shipped.isEmpty else { throw BenchmarkFailure("No shipped rule runs on \(String(describing: type))") }
        return (0..<count).map { index in
            var indicator = shipped[index % shipped.count]
            indicator.id = UUID()
            indicator.predicate = "(\(indicator.predicate)) AND NOT context == \"/nonexistent/\(index)\""
            return indicator
        }
    }

    /// Connects of one type that match no shipped indicator, as nearly every one does, from those `macmonitor stream`
    /// recorded (`Fixtures/macmonitor-3.1-resolver.jsonl`), each with native strings: for a Unix domain socket,
    /// platform binaries' connects to the resolver's, which the index finds and Unsigned code resolved a name rules out
    /// by the process's signing, and to syslog's, docker's and an ssh agent's, which the index rules out; for XPC, a
    /// platform binary's to the resolver's service and to others.
    ///
    /// - Parameters:
    ///   - type: `ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT` or `ES_EVENT_TYPE_NOTIFY_XPC_CONNECT`.
    ///   - count: How many.
    /// - Returns: The events, in turn.
    /// - Throws: The error reading the fixture or making them.
    func connectEvents(_ type: es_event_type_t, count: Int) throws -> [Message] {
        let recorded = try fixtureMessages("macmonitor-3.1-resolver.jsonl")
        var kinds: [Message]
        if type == ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT {
            let paths = ["/private/var/run/syslog", "/Users/a/.docker/run/docker.sock",
                         "/private/tmp/com.apple.launchd.x/Listeners"]
            kinds = Array(recorded.prefix(2)) + paths.map { path in
                var message = recorded[0]
                guard case .uipc_connect(var connect) = message.event else { return message }
                connect.file.path = path
                (message.event, message.target_path) = (.uipc_connect(connect), path)
                return message
            }
        } else {
            let services = ["com.apple.dnssd.service", "com.apple.trustd.agent", "com.apple.nsurlsessiond",
                            "com.apple.system.opendirectoryd.libinfo"]
            kinds = services.map { service in
                var message = recorded[2]
                message.process = recorded[0].process
                guard case .xpc_connect(var connect) = message.event else { return message }
                connect.service_name = service
                message.event = .xpc_connect(connect)
                return message
            }
        }
        kinds = try kinds.map(nativeCopy)
        return (0..<count).map { kinds[$0 % kinds.count] }
    }

    /// Many rules on one type's paths, as a shared set of file indicators has them: prefixes, suffixes, folders and
    /// patterns, each its own folder.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - type: Their event type.
    /// - Returns: The rules.
    func pathRules(_ count: Int, for type: es_event_type_t) -> [Indicator] {
        let check = "es_event_type == \"\(eventTypeToString(from: type))\""
        let comparisons = [#"target_path BEGINSWITH "/Library/Application Support/Vendor%d/""#,
                           #"target_path ENDSWITH[c] "/vendor%d.plist""#,
                           #"target_path CONTAINS[c] "/Caches/vendor%d/""#,
                           #"target_path LIKE[c] "/Users/*/Library/Vendor%d/*""#]
        return (0..<count).map { index in
            Indicator(name: "Path \(index)", description: "", symbol: "folder", color: .blue,
                      predicate: check + " AND " + String(format: comparisons[index % comparisons.count], index))
        }
    }
}
