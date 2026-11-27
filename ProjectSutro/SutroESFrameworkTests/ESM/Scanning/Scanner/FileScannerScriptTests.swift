//
//  FileScannerScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The scripts execs run
/// Pins how the scanner answers for scripts, with the stand-in rules (``standInRules()``): bytes an exec already read
/// are scanned in memory, a result is remembered with the rule files that ran and answers a request for those or
/// fewer, an exec looks a script up ignoring the change time a chmod leaves, a close that writes it again forgets that
/// answer, and a script Endpoint Security names that wasn't read is answered from memory alone.
final class FileScannerScriptTests: XCTestCase {
    /// The bytes an exec read are scanned in memory, with the rule files asked for, and XPScripts.yr too for a #! line
    /// that osascript runs. The file isn't read again: here it's gone.
    func testBytesReadAreScannedInMemory() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let text = "main-marker script-marker"
        let file = try scannedFile(text, name: "tool")
        XCTAssertEqual(unlink(file.path), 0)
        let job = FileScanner.Job(bytes: Data(text.utf8), info: file.info, files: [.xprotect])
        XCTAssertEqual(scan(job, with: scanner)?.rules, ["Main"])
        let jxa = "#!/usr/bin/osascript -l JavaScript\n" + text
        let other = try scannedFile(jxa, name: "jxa")
        let both = FileScanner.Job(bytes: Data(jxa.utf8), info: other.info, files: [.xprotect])
        XCTAssertEqual(scan(both, with: scanner)?.rules, ["Main", "Script"])
    }

    /// An exec looks its script up by device, inode, size and modification time. After a chmod, which changes only
    /// the change time, the close's result still answers it, while a close of that version would be scanned.
    func testAnExecIgnoresTheChangeTime() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let text = "#!/bin/sh\nmain-marker"
        let file = try scannedFile(text, name: "tool")
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
        Thread.sleep(forTimeInterval: 0.01)
        XCTAssertEqual(chmod(file.path, 0o755), 0)
        var changed = stat()
        XCTAssertEqual(stat(file.path, &changed), 0)
        XCTAssertNotEqual(FileScanVersion(changed), FileScanVersion(file.info), "The chmod changed the ctime.")
        let exec = FileScanner.Job(bytes: Data(text.utf8), info: changed, files: [.xprotect])
        guard case .answered(let found) = scanner.submit(exec, answer: { _ in XCTFail("Queued.") }) else {
            return XCTFail("The close's result didn't answer the exec.")
        }
        XCTAssertEqual(found.rules, ["Main"])
        XCTAssertEqual(scanner.submit(scanJob((file.path, changed)), answer: { _ in }), .queued,
                       "A close's lookup keeps the change time.")
    }

    /// A close that writes the script again with its old size and modification time (touch -r) forgets the old
    /// answer for execs, even when that close isn't scanned. Here it's busy: the window has room for one scan, and
    /// another is queued. The exec of what it wrote is scanned, and gets a result of its own.
    func testARewriteForgetsTheOldAnswer() throws {
        let scanner = try makeScanner(budget: FileScanBudget(window: FileScanBudget.minimumCost * 1.5))
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("#!/bin/sh\nmain-marker", name: "tool")
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
        let text = "#!/bin/sh\nxxxx-marker"
        let rewritten = try rewrite(file, with: text)
        let blocked = DispatchSemaphore(value: 0)
        scanner.status { _ in blocked.wait() }
        XCTAssertEqual(scanner.submit(scanJob(try scannedFile("other")), answer: { _ in }), .queued)
        XCTAssertEqual(scanner.submit(scanJob((file.path, rewritten)), answer: { _ in XCTFail("Queued.") }),
                       .answered(.notScanned(YaraScan.busy)))
        blocked.signal()
        /// The other job done, so the exec's scan is admitted rather than turned away busy.
        scanner.drain()
        let exec = FileScanner.Job(bytes: Data(text.utf8), info: rewritten, files: [.xprotect])
        let result = scan(exec, with: scanner)
        XCTAssertEqual(result?.status, YaraScan.scanned, "A scan of its own")
        XCTAssertEqual(result?.rules, [], "Its own result, not the old version's")
    }

    /// A job queued behind a scan that ran its rule files on its content is answered with that scan's result, without
    /// a scan of its own. The osascript exec of a `#!/usr/bin/env osascript` script waits behind the env exec's, which
    /// asked for less but ran both rule files once it read the first line. Here the osascript exec's own bytes hold no
    /// marker, so a scan of them would match nothing.
    func testAJobQueuedBehindAScanThatCoveredItIsntScanned() throws {
        let gate = DispatchSemaphore(value: 0)
        let scanner = try makeScanner(gate: gate)
        scanner.acquire()
        defer { scanner.release() }
        let text = "#!/usr/bin/env osascript\nmain-marker script-marker"
        let file = try scannedFile(text, name: "prompt")
        let unmarked = Data(text.replacingOccurrences(of: "marker", with: "xxxxxx").utf8)
        let answers = Recorded<YaraScan>()
        let env = FileScanner.Job(bytes: Data(text.utf8), info: file.info, files: [.xprotect])
        XCTAssertEqual(scanner.submit(env, answer: answers.append), .queued)
        let osascript = FileScanner.Job(bytes: unmarked, info: file.info, files: [.xprotect, .scripts])
        XCTAssertEqual(scanner.submit(osascript, answer: answers.append), .queued, "It asks for more than env did")
        gate.signal()
        XCTAssertTrue(waitUntil { answers.all.count == 2 })
        XCTAssertEqual(answers.all.map(\.rules), [["Main", "Script"], ["Main", "Script"]])
    }

    /// A queued exec is answered only by a result that describes its script's content. A close of the same version
    /// that its writer couldn't read says nothing of it, so the bytes the exec read are scanned.
    func testAQueuedExecIsntAnsweredByAnUnreadableClose() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let text = "#!/bin/sh\nmain-marker"
        let file = try scannedFile(text, name: "tool")
        let stranger = FileReader(uid: 502, gid: 30)
        let close = FileScanner.Job(path: file.path, info: file.info, reader: stranger, files: [.xprotect])
        XCTAssertEqual(scan(close, with: scanner)?.status, YaraScan.unreadable)
        let exec = FileScanner.Job(bytes: Data(text.utf8), info: file.info, files: [.xprotect])
        XCTAssertEqual(scan(exec, with: scanner)?.rules, ["Main"])
    }

    /// A script Endpoint Security names that the lane couldn't read is answered from memory alone, and is unreadable
    /// otherwise.
    func testAnUnreadScriptIsAnsweredFromMemory() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker", name: "tool")
        let unread = FileScanner.Job(unread: FileScanVersion(file.info), files: [.xprotect])
        XCTAssertEqual(scanner.submit(unread, answer: { _ in XCTFail("Queued.") }),
                       .answered(.notScanned(YaraScan.unreadable)))
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
        XCTAssertEqual(scan(unread, with: scanner)?.rules, ["Main"])
    }

    /// A JXA script's close asks for XProtect.yara, and its first line adds XPScripts.yr, so its result answers the
    /// osascript exec that asks for both. A shell script's result ran XProtect.yara alone and doesn't answer a
    /// request for both, which is scanned.
    func testAResultAnswersTheRuleFilesItRan() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let jxa = try scannedFile("#!/usr/bin/osascript -l JavaScript\nmain-marker script-marker", name: "jxa")
        XCTAssertEqual(scan(scanJob(jxa), with: scanner)?.rules, ["Main", "Script"])
        guard case .answered(let remembered) = scanner.submit(scanJob(jxa, files: [.xprotect, .scripts]),
                                                              answer: { _ in XCTFail("Queued.") }) else {
            return XCTFail("The JXA script's result didn't answer.")
        }
        XCTAssertEqual(remembered.rules, ["Main", "Script"])

        let shell = try scannedFile("#!/bin/sh\nmain-marker script-marker", name: "tool.sh")
        XCTAssertEqual(scan(scanJob(shell), with: scanner)?.rules, ["Main"])
        XCTAssertEqual(scan(scanJob(shell, files: [.xprotect, .scripts]), with: scanner)?.rules, ["Main", "Script"],
                       "XPScripts.yr didn't run on the shell script.")
        XCTAssertEqual(scan(scanJob(shell), with: scanner)?.rules, ["Main", "Script"],
                       "The result that ran more rule files answers a request for fewer.")
    }
}
