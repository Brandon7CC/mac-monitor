//
//  ProcessLineageTests+Discovery.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Lookups
extension ProcessLineageTests {
    /// A process the table wasn't told of takes the parent its event names: for a lookup that comes before its
    /// fork is handled, and for an exec of a process that was never seen forking.
    func testAProcessTheTableWasNotToldOf() {
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        XCTAssertEqual(ancestors(of: key(200, 2)), [])
        XCTAssertEqual(ancestors(of: key(200, 2), parent: key(100, 1)), ["/bin/zsh"])
        XCTAssertEqual(ancestors(of: key(200, 2), parent: key(555, 1)), [])

        lineage.exec(program(300, 9, "/usr/bin/true"), replacing: key(300, 8), parent: key(100, 1), at: 0)
        XCTAssertEqual(ancestors(of: key(300, 9)), ["/bin/zsh"])
        lineage.exec(program(400, 9, "/usr/bin/true"), replacing: key(400, 8), parent: key(777, 3), at: 0)
        XCTAssertEqual(ancestors(of: key(400, 9)), ["777.3"], "An unknown parent is listed by its key")
    }

    /// A lane ahead of the one that reports execs asks about a program the table hasn't been told of: it has the
    /// ancestors of the newest program known of its pid. So does a parent named by a program the table hasn't been
    /// told of, and a program the pid ran before, once it's forgotten. When no program of the pid is known,
    /// nothing stands in for it.
    func testAProgramTheTableHasNotBeenToldOfYet() {
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        lineage.fork(key(200, 2), from: key(100, 1))
        XCTAssertEqual(ancestors(of: key(200, 3)), ["/bin/zsh"], "Its exec hasn't been reported")
        XCTAssertEqual(ancestors(of: key(300, 9), parent: key(200, 3)), ["/bin/zsh", "/bin/zsh"],
                       "Neither its fork nor its parent's exec has been reported")
        XCTAssertEqual(ancestors(of: key(200, 1)), ["/bin/zsh"], "A program the pid ran before")

        lineage.exec(program(200, 3, "/bin/sh"), replacing: key(200, 2), at: 0)
        XCTAssertEqual(ancestors(of: key(300, 9), parent: key(200, 4)), ["/bin/sh", "/bin/zsh"])
        lineage.exit(key(200, 3), at: 0)
        lineage.exit(key(999, 1), at: ProcessLineage.lingers)
        XCTAssertEqual(ancestors(of: key(200, 5)), [])
        XCTAssertEqual(ancestors(of: key(300, 9), parent: key(200, 4)), [])
    }

    /// A lookup for a process the table knows nothing of, nor of its parent, can read the parents from the system:
    /// each running one, up to one the table knows. A parent that exec'd since its child named it is found by its
    /// pid. One that's gone is kept by its key alone, so the next lookup reads nothing. Nothing is read for a
    /// process the table knows, a child of launchd, or a lookup that didn't ask.
    func testALookupReadsParentsFromTheSystem() {
        var asked: [Int32] = []
        let running: [Int32: (program: ProcessProgram, parent: Int32)] = [
            400: (program(400, 9, "/bin/bash"), 300), 300: (program(300, 1, "/usr/bin/python3"), 100),
            100: (program(100, 1, "/bin/zsh"), 1),
        ]
        lineage = ProcessLineage { pid in
            asked.append(pid)
            return running[pid]
        }
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        XCTAssertEqual(ancestors(of: key(500, 2), parent: key(400, 8)), [], "It didn't ask")
        XCTAssertEqual(lineage.ancestors(of: key(500, 2), parent: key(400, 8), reading: true).map(\.path),
                       ["/bin/bash", "/usr/bin/python3", "/bin/zsh"])
        XCTAssertEqual(asked, [400, 300, 100], "Up to the one the table knows")
        XCTAssertEqual(lineage.program(key(400, 9))?.path, "/bin/bash", "Under the key it has now")
        XCTAssertNil(lineage.program(key(400, 8)))
        XCTAssertEqual(lineage.discoveries.read, 1)

        asked = []
        XCTAssertEqual(lineage.ancestors(of: key(500, 2), parent: key(400, 8), reading: true).count, 3)
        XCTAssertEqual(lineage.ancestors(of: key(600, 2), parent: key(1, 7), reading: true), [])
        XCTAssertEqual(lineage.ancestors(of: key(300, 1), reading: true).map(\.path), ["/bin/zsh"])
        XCTAssertEqual(asked, [])

        XCTAssertEqual(lineage.discoveries.unanswered, 0)
        XCTAssertEqual(lineage.waits.count, 0)

        lineage.exec(program(400, 10, "/bin/sh"), replacing: key(400, 9), at: 0)
        XCTAssertEqual(ancestors(of: key(400, 10)), ["/usr/bin/python3", "/bin/zsh"],
                       "What was read stands until the exec is reported")
    }

    /// A process the table doesn't know, whose event names no parent, as a network flow's doesn't, is read from the
    /// system with its parents. A flow that connects before the table hears of its process's fork still has its
    /// ancestors, and the next lookup reads nothing.
    func testALookupWithNoParentReadsTheProcess() {
        var asked: [Int32] = []
        let running: [Int32: (program: ProcessProgram, parent: Int32)] = [
            700: (program(700, 3, "/usr/bin/curl"), 100), 100: (program(100, 1, "/bin/zsh"), 1),
        ]
        lineage = ProcessLineage { pid in
            asked.append(pid)
            return running[pid]
        }
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        XCTAssertEqual(lineage.ancestors(of: key(700, 3), reading: true).map(\.path), ["/bin/zsh"])
        XCTAssertEqual(asked, [700, 100])
        asked = []
        XCTAssertEqual(lineage.ancestors(of: key(700, 3), reading: true).count, 1)
        XCTAssertEqual(lineage.ancestors(of: key(1, 7), reading: true), [])
        XCTAssertEqual(asked, [], "Nothing is read for a known process or launchd")
    }

    /// A process's command line is read by its own key. One the table knows is answered at once, a forked child's
    /// being its parent's. One it doesn't know is read from the system, with its parents. One whose pid the table
    /// knows only another program of is waited for, and never answered with that program's.
    func testACommandLineIsReadByItsOwnKey() {
        var asked: [Int32] = []
        let running: [Int32: (program: ProcessProgram, parent: Int32)] = [
            700: (program(700, 3, "/usr/bin/curl"), 100), 100: (program(100, 1, "/bin/zsh"), 1),
        ]
        lineage = ProcessLineage(reader: { pid in
            asked.append(pid)
            return running[pid]
        }, patience: 0.05, waitBudget: 30)
        lineage.seed([(program(100, 1, "/bin/zsh"), 1), (program(810, 1, "/usr/bin/python3"), 100)])
        lineage.fork(key(800, 1), from: key(100, 1))
        XCTAssertEqual(lineage.commandLine(of: key(800, 1), at: 0), "/bin/zsh --flag", "A fork runs its parent's")
        XCTAssertEqual(asked, [])
        XCTAssertEqual(lineage.commandLine(of: key(700, 3), at: 0), "/usr/bin/curl --flag")
        XCTAssertEqual(asked, [700, 100])
        XCTAssertNil(lineage.commandLine(of: key(810, 2), at: 0), "Not python3's")
        XCTAssertNil(lineage.commandLine(of: key(1, 7), at: 0))
        XCTAssertNil(ProcessLineage().commandLine(of: key(700, 3), at: 0), "No reader, no read")
    }

    /// A parent that's gone from the system too is waited for: its fork is on its way, and the lookup has the
    /// ancestors once the table is told. One the table is never told of is given up on when the lookup's patience
    /// runs out, counted, and kept by its key alone, so the process's next event neither looks nor waits.
    func testALookupWaitsForAProcessThatIsGone() {
        var asked: [Int32] = []
        lineage = ProcessLineage(reader: { pid in
            asked.append(pid)
            return nil
        }, patience: 10, waitBudget: 30)
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        let table = lineage
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) {
            table.fork(self.key(200, 2), from: self.key(100, 1))
        }
        XCTAssertEqual(lineage.ancestors(of: key(300, 4), parent: key(200, 3), reading: true).map(\.key),
                       [key(200, 2), key(100, 1)])
        XCTAssertEqual(asked, [200])
        XCTAssertEqual(lineage.waits.count, 1)
        XCTAssertGreaterThanOrEqual(lineage.waits.longest, 0.04)
        XCTAssertLessThan(lineage.waits.longest, 5)
        XCTAssertEqual(lineage.discoveries.unanswered, 0)

        lineage = ProcessLineage(reader: { _ in nil }, patience: 0.05, waitBudget: 30)
        XCTAssertEqual(lineage.ancestors(of: key(500, 2), parent: key(400, 1), reading: true),
                       [ProcessProgram(key: key(400, 1))])
        XCTAssertEqual(lineage.discoveries.unanswered, 1)
        XCTAssertGreaterThanOrEqual(lineage.waits.longest, 0.04)
        XCTAssertEqual(lineage.ancestors(of: key(500, 2), parent: key(400, 1), reading: true).count, 1)
        XCTAssertEqual(lineage.discoveries.read, 1, "The next lookup neither reads nor waits")
        XCTAssertEqual(lineage.waits.count, 1)
    }

    /// Endpoint Security hands the table's client its events in order, so a lookup for an event waits only until
    /// the client is told of one as late: by then it has been told of every fork and exec before the event. An
    /// earlier one doesn't end the wait. A lookup for an event the client is already past doesn't wait at all.
    func testALookupWaitsUntilTheTableIsToldOfItsEventsTime() {
        lineage = ProcessLineage(reader: { _ in nil }, patience: 10, waitBudget: 30)
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        let table = lineage
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) { table.told(upTo: 999) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            table.fork(self.key(200, 2), from: self.key(100, 1))
            table.told(upTo: 1_000)
        }
        XCTAssertEqual(lineage.ancestors(of: key(300, 4), parent: key(200, 3), reading: true, at: 1_000).map(\.key),
                       [key(200, 2), key(100, 1)])
        XCTAssertGreaterThanOrEqual(lineage.waits.longest, 0.09, "An earlier event didn't end the wait")
        XCTAssertLessThan(lineage.waits.longest, 5)

        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { table.told(upTo: 2_000) }
        let started = Date()
        XCTAssertEqual(lineage.ancestors(of: key(500, 2), parent: key(400, 1), reading: true, at: 1_500),
                       [ProcessProgram(key: key(400, 1))], "Told of a later event, and still not of the parent")
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "It didn't wait its patience out")
        XCTAssertEqual(lineage.waits.count, 2)
        XCTAssertEqual(lineage.discoveries.unanswered, 1)

        XCTAssertEqual(lineage.ancestors(of: key(700, 2), parent: key(600, 1), reading: true, at: 2_000).count, 1)
        XCTAssertEqual(lineage.waits.count, 2, "The client is already past the event")
        XCTAssertEqual(lineage.discoveries.unanswered, 2)
    }

    /// A capture lane that tells the table of an exec first names a parent the table knows nothing of, which is
    /// kept by its key alone. A lookup learns of it as of any other: from the system while it runs, under the key
    /// it has now if it exec'd since, and from the table's client once it's gone. One a lookup gave up on isn't
    /// waited for again.
    func testAnAncestorKnownByItsKeyAloneIsLearned() {
        var running: [Int32: (program: ProcessProgram, parent: Int32)] = [200: (program(200, 2, "/bin/bash"), 100)]
        lineage = ProcessLineage(reader: { running[$0] }, patience: 10, waitBudget: 30)
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        lineage.exec(program(300, 5, "/usr/bin/osascript"), replacing: key(300, 4), parent: key(200, 2), at: 0)
        XCTAssertEqual(ancestors(of: key(300, 5)), ["200.2"], "Without asking, only its key")
        XCTAssertEqual(lineage.ancestors(of: key(300, 5), reading: true).map(\.path), ["/bin/bash", "/bin/zsh"])
        XCTAssertEqual(lineage.waits.count, 0)

        running[400] = (program(400, 9, "/usr/bin/env"), 100)
        lineage.exec(program(500, 5, "/usr/bin/true"), replacing: key(500, 4), parent: key(400, 8), at: 0)
        XCTAssertEqual(lineage.ancestors(of: key(500, 5), reading: true).map { $0.path ?? $0.key.description },
                       ["400.8", "/bin/zsh"], "It exec'd since: its ancestors are the same")

        let table = lineage
        lineage.exec(program(700, 5, "/usr/bin/true"), replacing: key(700, 4), parent: key(600, 2), at: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.02) {
            table.fork(self.key(600, 2), from: self.key(100, 1))
        }
        XCTAssertEqual(lineage.ancestors(of: key(700, 5), reading: true, at: 50).map(\.path), ["/bin/zsh", "/bin/zsh"],
                       "Gone from the system: its fork came")
        XCTAssertEqual(lineage.waits.count, 1)

        lineage = ProcessLineage(reader: { _ in nil }, patience: 0.05, waitBudget: 30)
        lineage.exec(program(900, 5, "/usr/bin/true"), replacing: key(900, 4), parent: key(800, 2), at: 0)
        XCTAssertEqual(lineage.ancestors(of: key(900, 5), reading: true, at: 50).map(\.key), [key(800, 2)])
        XCTAssertEqual(lineage.discoveries.unanswered, 1)
        let waits = lineage.waits.count
        XCTAssertEqual(lineage.ancestors(of: key(900, 5), reading: true, at: 50).map(\.key), [key(800, 2)])
        XCTAssertEqual(lineage.waits.count, waits, "Given up on once")
        XCTAssertEqual(lineage.discoveries.unanswered, 1)
    }

    /// Lookups wait in vain only so long in all in any one second: once that's spent, one that would wait gives up
    /// at once, so a table that's told nothing can't hold a capture lane up. A wait that was answered isn't counted.
    func testLookupsWaitWithinABudget() {
        lineage = ProcessLineage(reader: { _ in nil }, patience: 5, waitBudget: 0.01)
        let table = lineage
        for pid in Int32(200)..<203 {
            let time = UInt64(pid) * 10
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.02) {
                table.fork(self.key(pid, 2), from: self.key(100, 1))
                table.told(upTo: time)
            }
            let ancestors = lineage.ancestors(of: key(pid + 1_000, 2), parent: key(pid, 2), reading: true, at: time)
            XCTAssertEqual(ancestors.map(\.key), [key(pid, 2), key(100, 1)])
        }
        XCTAssertEqual(lineage.waits.count, 3, "Each was answered, so each could wait")

        lineage = ProcessLineage(reader: { _ in nil }, patience: 0.05, waitBudget: 0.06)
        let started = Date()
        for pid in Int32(400)..<420 {
            XCTAssertEqual(lineage.ancestors(of: key(pid + 1_000, 2), parent: key(pid, 1), reading: true).count, 1)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.9, "Twenty lookups didn't each wait")
        XCTAssertEqual(lineage.discoveries.unanswered, 20)
        XCTAssertTrue((1...2).contains(lineage.waits.count), "Only what the budget allowed: \(lineage.waits.count)")
        XCTAssertEqual(ProcessLineage().patience, 0.3, "Longer than Endpoint Security holds a quiet client's events")
    }
}
