//
//  XPCProtocolSnapshotTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import ObjectiveC
@testable import SutroESFramework


// MARK: - XPC protocols against 3.0.0
/// Pins the XPC protocols against the selectors v3.0.0 shipped (`xpc-selectors-3.0.0.json`, compiled from the
/// protocols at that tag). NSXPC closes the connection that sends a message its peer's interface doesn't have, so a
/// call added since reaches a 3.0.0 peer only on a connection that may close. On Mac Monitor's own connection that
/// stops capture. A new call fails ``testNothingIsAddedUnguarded()`` until ``added`` says how it's kept off such a
/// connection, and a 3.0.0 call that changes or goes fails ``testThreeZeroCallsAreUnchanged()``: its Objective-C
/// types, which write every object as `@`, and the classes NSXPC lets each argument and reply argument be.
final class XPCProtocolSnapshotTests: XCTestCase {
    /// The protocols a peer of another release calls, under their names in the fixture: the Security Extension's
    /// (``SensorProtocol``, ``StreamProtocol``), and those it calls back (``AppAgentProtocol``,
    /// ``StreamReaderProtocol``).
    private let protocols: [String: Protocol] = [
        "SensorProtocol": SensorProtocol.self, "StreamProtocol": StreamProtocol.self,
        "AppAgentProtocol": AppAgentProtocol.self, "StreamReaderProtocol": StreamReaderProtocol.self,
    ]

    /// The calls added since 3.0.0, by protocol, and how each is kept off a connection a 3.0.0 peer would close. The
    /// Security Extension can't tell which release the app or `macmonitor` is, so it calls back nothing new.
    private let added: [String: [String: String]] = [
        "SensorProtocol": [
            "indicators:reply:": "Sent once a list on a connection of its own answers (indicatorSupport).",
            "commandLineAccessWithReply:": "Sent on a connection of its own (SensorClient.probe).",
            "setCommandLineAccess:reply:": "Sent once commandLineAccess answers (commandLineAccessSupport).",
        ],
        "StreamProtocol": [
            "indicators:reply:": "Sent before a stream starts, on a connection that ends with exit 69 if it closes.",
        ],
    ]

    /// The interfaces this build gives each protocol's connections, under the fixture's names: their classes are the
    /// ones NSXPC checks a message against.
    private let interfaces: [String: NSXPCInterface] = [
        "SensorProtocol": SensorXPC.sensorInterface, "StreamProtocol": SensorXPC.streamInterface,
        "AppAgentProtocol": SensorXPC.agentInterface, "StreamReaderProtocol": SensorXPC.streamReaderInterface,
    ]

    /// Every call v3.0.0 shipped is still there, with the same Objective-C types, and each argument and reply
    /// argument takes the same classes. A reply that lost an argument raises instead of failing, as NSXPC does when
    /// asked about one past the last.
    func testThreeZeroCallsAreUnchanged() throws {
        let fixture = try fixtureObject("xpc-selectors-3.0.0.json")
        let shippedClasses = try XCTUnwrap(fixture["classes"] as? [String: [String: [String: [String]]]])
        for (name, shipped) in try threeZero() {
            let current = methods(of: try XCTUnwrap(protocols[name], name))
            let interface = try XCTUnwrap(interfaces[name], name)
            for (selector, types) in shipped {
                XCTAssertEqual(current[selector], types, "\(name) changed or dropped \(selector) since 3.0.0")
                let classes = try XCTUnwrap(shippedClasses[name]?[selector], "No classes for \(name) \(selector)")
                guard current[selector] == types else { continue }
                for (ofReply, key) in [(false, "arguments"), (true, "reply")] {
                    let expected = try XCTUnwrap(classes[key])
                    XCTAssertEqual(self.classes(interface, selector, count: expected.count, ofReply: ofReply),
                                   expected, "\(name) \(selector) takes other classes in its \(key) than 3.0.0")
                }
            }
        }
    }

    /// Each call added since 3.0.0 is one ``added`` lists with its guard.
    func testNothingIsAddedUnguarded() throws {
        let shipped = try threeZero()
        XCTAssertEqual(Set(shipped.keys), Set(protocols.keys))
        for (name, proto) in protocols {
            let new = Set(methods(of: proto).keys).subtracting(shipped[name, default: [:]].keys)
            XCTAssertEqual(new, Set(added[name, default: [:]].keys), """
                \(name) differs from 3.0.0 by calls this test doesn't list. A 3.0.0 peer closes the connection that \
                sends one: send it on a connection of its own (SensorClient.probe) or once one has answered \
                (SensorSupport), then list it with its guard.
                """)
        }
    }

    /// The 3.0.0 Security Extension the skew tests run against exports exactly what v3.0.0 did.
    func testTheOlderFakesExportThreeZero() throws {
        let shipped = try threeZero()
        XCTAssertEqual(methods(of: SensorProtocolBeforeIndicators.self), shipped["SensorProtocol"])
        XCTAssertEqual(methods(of: StreamProtocolBeforeIndicators.self), shipped["StreamProtocol"])
    }

    // MARK: Helpers
    /// The selectors v3.0.0 shipped, by protocol.
    ///
    /// - Returns: Each protocol's selectors and their Objective-C types.
    /// - Throws: If the fixture is missing or isn't shaped so.
    private func threeZero() throws -> [String: [String: String]] {
        let fixture = try fixtureObject("xpc-selectors-3.0.0.json")
        XCTAssertEqual(fixture["release"] as? String, "3.0.0")
        return try XCTUnwrap(fixture["protocols"] as? [String: [String: String]])
    }

    /// The classes `interface` lets each of a call's first arguments, or its reply's, be, as the fixture writes them.
    ///
    /// - Parameters:
    ///   - interface: The interface NSXPC checks messages against.
    ///   - selector: The call's selector.
    ///   - count: How many arguments to read, from the first.
    ///   - ofReply: Read the reply block's arguments rather than the call's.
    /// - Returns: Each argument's class names, sorted and joined by `", "`: empty for one that isn't an object.
    private func classes(_ interface: NSXPCInterface, _ selector: String, count: Int, ofReply: Bool) -> [String] {
        (0..<count).map { index in
            interface.classes(for: NSSelectorFromString(selector), argumentIndex: index, ofReply: ofReply)
                .compactMap { ($0.base as? AnyClass).map(NSStringFromClass) }.sorted().joined(separator: ", ")
        }
    }

    /// A protocol's instance methods, required or not, with those of the protocols it inherits.
    ///
    /// - Parameter proto: The protocol.
    /// - Returns: Each method's selector and Objective-C types.
    private func methods(of proto: Protocol) -> [String: String] {
        var found: [String: String] = [:]
        for required in [true, false] {
            var count: UInt32 = 0
            guard let list = protocol_copyMethodDescriptionList(proto, required, true, &count) else { continue }
            defer { free(list) }
            for method in UnsafeBufferPointer(start: list, count: Int(count)) {
                guard let selector = method.name, let types = method.types else { continue }
                found[NSStringFromSelector(selector)] = String(cString: types)
            }
        }
        var count: UInt32 = 0
        guard let inherited = protocol_copyProtocolList(proto, &count) else { return found }
        for index in 0..<Int(count) {
            found.merge(methods(of: inherited[index])) { mine, _ in mine }
        }
        return found
    }
}
