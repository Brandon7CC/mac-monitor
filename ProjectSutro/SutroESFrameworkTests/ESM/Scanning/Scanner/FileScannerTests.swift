//
//  FileScannerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/24/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The scanner
/// Pins the scanner against real files and this Mac's libyara, with small rule sets compiled here standing in for
/// Apple's: what a scan answers, how a version is remembered and rescanned, that a scan leaves the access time alone,
/// and how the budget, the size cap and the users decide what's scanned.
final class FileScannerTests: XCTestCase {
    /// A written file is scanned with the rule files that apply, every match named, and Apple's report-only rules
    /// listed.
    func testAWrittenFileIsScanned() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker hunt-marker script-marker")
        let mainOnly = try XCTUnwrap(scan(scanJob(file), with: scanner))
        XCTAssertEqual(mainOnly.status, YaraScan.scanned)
        XCTAssertEqual(mainOnly.xprotect_version, "5377")
        XCTAssertEqual(Set(mainOnly.rules), ["Main", "Hunt"])
        XCTAssertEqual(Set(mainOnly.names), ["TEST.MAIN", "HUNT.TEST"])
        XCTAssertEqual(mainOnly.report_only, ["Hunt"])

        let other = try scannedFile("main-marker script-marker", name: "script")
        let both = try XCTUnwrap(scan(scanJob(other, files: [.xprotect, .scripts]), with: scanner))
        XCTAssertEqual(both.rules, ["Main", "Script"])
        XCTAssertEqual(both.names, ["TEST.MAIN", "Script"], "A rule without a description is named by itself.")

        let clean = try scannedFile("nothing to see", name: "clean")
        XCTAssertEqual(scan(scanJob(clean), with: scanner), YaraScan(status: YaraScan.scanned, xprotectVersion: "5377"))
    }

    /// JavaScript that a `#!` line has `osascript` run also gets XPScripts.yr. Its type is the same as any other
    /// JavaScript's, so its job asks for XProtect.yara only, and the scanner reads the first line.
    func testJavaScriptForAutomationGetsTheScriptRules() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        for line in ["#!/usr/bin/osascript -l JavaScript", "#!/usr/bin/env osascript -l JavaScript"] {
            let file = try scannedFile(line + "\nmain-marker script-marker", name: "jxa")
            XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main", "Script"], line)
        }
        let node = try scannedFile("#!/usr/bin/env node\nmain-marker script-marker", name: "node")
        XCTAssertEqual(scan(scanJob(node), with: scanner)?.rules, ["Main"],
                       "Only what osascript runs gets XPScripts.yr.")
        let text = try scannedFile("main-marker script-marker\n#!/usr/bin/osascript -l JavaScript", name: "text")
        XCTAssertEqual(scan(scanJob(text), with: scanner)?.rules, ["Main"], "The #! line has to be first.")
    }

    /// A version is scanned once: asking again gets the remembered result. A rewrite with its old modification time
    /// put back is a new version, by its change time, and is scanned again.
    func testAVersionIsScannedOnceAndARewriteAgain() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker")
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
        guard case .answered(let remembered) = scanner.submit(scanJob(file), answer: { _ in XCTFail("Queued.") }) else {
            return XCTFail("The result wasn't remembered.")
        }
        XCTAssertEqual(remembered.rules, ["Main"])

        /// The same size and modification time, a new change time: what `touch -r` leaves after a rewrite.
        Thread.sleep(forTimeInterval: 0.01)
        try Data("xxxx-marker".utf8).write(to: URL(fileURLWithPath: file.path))
        var times = [timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)), file.info.st_mtimespec]
        XCTAssertEqual(utimensat(AT_FDCWD, file.path, &times, 0), 0)
        var rewritten = stat()
        stat(file.path, &rewritten)
        XCTAssertEqual(rewritten.st_size, file.info.st_size)
        XCTAssertEqual(rewritten.st_mtimespec.tv_nsec, file.info.st_mtimespec.tv_nsec)
        XCTAssertEqual(scan(scanJob((file.path, rewritten)), with: scanner)?.rules, [])
    }

    /// A file that changed since the event isn't scanned as the event's version, and says so.
    func testAChangedFileSaysSo() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker")
        Thread.sleep(forTimeInterval: 0.01)
        try Data("main-marker and more".utf8).write(to: URL(fileURLWithPath: file.path))
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.status, YaraScan.changed)
    }

    /// A file renamed into place right after its close is still scanned: a rename changes its change time but not
    /// what it holds, and the path the close named is gone, so it's found by its device and inode.
    func testAFileRenamedAfterItsCloseIsScanned() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker", name: ".tool.tmp")
        let destination = (file.path as NSString).deletingLastPathComponent + "/tool"
        Thread.sleep(forTimeInterval: 0.01)
        XCTAssertEqual(rename(file.path, destination), 0)
        var renamed = stat()
        stat(destination, &renamed)
        XCTAssertNotEqual(renamed.st_ctimespec.tv_nsec, file.info.st_ctimespec.tv_nsec, "A rename changed the ctime.")
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
    }

    /// Scanning reads the file without updating its access time.
    func testAScanLeavesTheAccessTimeAlone() throws {
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        var file = try scannedFile("main-marker")
        var times = [timespec(tv_sec: 1_600_000_000, tv_nsec: 0), timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT))]
        XCTAssertEqual(utimensat(AT_FDCWD, file.path, &times, 0), 0)
        stat(file.path, &file.info)
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.rules, ["Main"])
        var after = stat()
        stat(file.path, &after)
        XCTAssertEqual(after.st_atimespec.tv_sec, 1_600_000_000)
    }

    /// A file over the cap isn't read, and nothing is scanned without a user.
    func testTheCapAndTheUsers() throws {
        let scanner = try makeScanner(maxBytes: 8)
        let file = try scannedFile("main-marker")
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.status, YaraScan.unavailable, "Nobody is scanning.")
        scanner.acquire()
        defer { scanner.release() }
        XCTAssertEqual(scan(scanJob(file), with: scanner)?.status, YaraScan.tooLarge)
    }

    /// A file whose cost the bucket doesn't hold is over budget, and the budget refills with time.
    func testTheBudgetDecides() throws {
        var now: TimeInterval = 0
        let budget = FileScanBudget(refillPerSecond: 0.05, capacity: 0.001, window: 1, clock: { now })
        let scanner = try makeScanner(budget: budget)
        scanner.acquire()
        defer { scanner.release() }
        let large = try scannedFile(String(repeating: "a", count: 1 << 20), name: "large")
        XCTAssertEqual(scan(scanJob(large), with: scanner)?.status, YaraScan.overBudget)
        let small = try scannedFile("main-marker", name: "small")
        XCTAssertEqual(scan(scanJob(small), with: scanner)?.status, YaraScan.scanned)
        now += 1
        let later = try scannedFile("main-marker", name: "later")
        XCTAssertEqual(scan(scanJob(later), with: scanner)?.status, YaraScan.scanned)
    }

    /// Requests for a version while its scan is queued wait for that one scan.
    func testRequestsWhileQueuedShareOneScan() throws {
        let loads = ScannerLoads()
        let scanner = try makeScanner(loads: loads)
        scanner.acquire()
        defer { scanner.release() }
        let file = try scannedFile("main-marker")
        var answers: [YaraScan] = []
        let both = expectation(description: "both answered")
        both.expectedFulfillmentCount = 2
        let lock = NSLock()
        for _ in 0..<2 {
            let submission = scanner.submit(scanJob(file)) { scan in
                lock.lock(); answers.append(scan); lock.unlock()
                both.fulfill()
            }
            if case .answered(let now) = submission {
                lock.lock(); answers.append(now); lock.unlock()
                both.fulfill()
            }
        }
        wait(for: [both], timeout: 10)
        XCTAssertEqual(answers.map(\.rules), [["Main"], ["Main"]])
        XCTAssertEqual(loads.count, 1)
    }

    /// The last release drops the rules, and the next acquire loads them again.
    func testTheLastReleaseDropsTheRules() throws {
        let loads = ScannerLoads()
        let scanner = try makeScanner(loads: loads)
        scanner.acquire()
        scanner.acquire()
        scanner.drain()
        XCTAssertTrue(scanner.hasRulesLoaded)
        scanner.release()
        scanner.drain()
        XCTAssertTrue(scanner.hasRulesLoaded, "A session still scans.")
        scanner.release()
        scanner.drain()
        XCTAssertFalse(scanner.hasRulesLoaded)
        scanner.acquire()
        defer { scanner.release() }
        XCTAssertEqual(scan(scanJob(try scannedFile("main-marker")), with: scanner)?.rules, ["Main"])
        XCTAssertEqual(loads.count, 2)
    }

    /// Where freed memory comes back (YARA 3), idle rules are dropped, and the next scan loads them again.
    func testIdleRulesAreDroppedOnYara3() throws {
        let loads = ScannerLoads()
        let scanner = try makeScanner(generation: .yara3, idleUnload: 0.05, loads: loads)
        scanner.acquire()
        defer { scanner.release() }
        XCTAssertEqual(scan(scanJob(try scannedFile("main-marker")), with: scanner)?.rules, ["Main"])
        Thread.sleep(forTimeInterval: 0.2)
        scanner.drain()
        XCTAssertFalse(scanner.hasRulesLoaded)
        XCTAssertEqual(scan(scanJob(try scannedFile("main-marker", name: "again")), with: scanner)?.rules, ["Main"])
        XCTAssertEqual(loads.count, 2)
    }

    /// The status says what's loaded now. Asking loads nothing. Before a session acquires the rules none are loaded.
    /// Once they're loaded, it says why a rule file didn't load. After the last release none are loaded again. Rules
    /// that can't load say why.
    func testTheStatusSaysWhatsLoaded() throws {
        let loads = ScannerLoads()
        let partial = XProtectRules(version: "5377", sets: [:], problems: [.scripts: "XPScripts.yr didn't compile."])
        let scanner = FileScanner(generation: .yara4, currentVersion: { "5377" }, load: {
            loads.count += 1
            return .success(partial)
        })
        XCTAssertEqual(try awaitCallback(scanner.status), XProtectRuleStatus(state: .unloaded))
        scanner.acquire()
        XCTAssertEqual(try awaitCallback(scanner.status), XProtectRuleStatus(
            state: .loaded, version: "5377", problems: ["XPScripts.yr didn't compile."]))
        scanner.release()
        XCTAssertEqual(try awaitCallback(scanner.status), XProtectRuleStatus(state: .unloaded))
        XCTAssertEqual(loads.count, 1, "Asking loaded nothing.")
        let broken = FileScanner(generation: .yara4, currentVersion: { nil },
                                 load: { .failure(.missing("No rules here.")) })
        broken.acquire()
        defer { broken.release() }
        XCTAssertEqual(try awaitCallback(broken.status),
                       XProtectRuleStatus(state: .failed, problems: ["No rules here."]))
    }

    /// Asking doesn't load rules dropped after a quiet minute (YARA 3) while a session still holds the scanner.
    func testAskingLeavesIdleRulesUnloaded() throws {
        let loads = ScannerLoads()
        let scanner = try makeScanner(generation: .yara3, idleUnload: 0.05, loads: loads)
        scanner.acquire()
        defer { scanner.release() }
        XCTAssertEqual(scan(scanJob(try scannedFile("main-marker")), with: scanner)?.rules, ["Main"])
        Thread.sleep(forTimeInterval: 0.2)
        scanner.drain()
        XCTAssertEqual(try awaitCallback(scanner.status), XProtectRuleStatus(state: .unloaded))
        XCTAssertFalse(scanner.hasRulesLoaded)
        XCTAssertEqual(loads.count, 1, "Asking loaded nothing.")
    }

    /// Rules that can't load make every scan unavailable, with the reason logged once per load.
    func testUnavailableRules() throws {
        let scanner = FileScanner(generation: .yara4, currentVersion: { nil },
                                  load: { .failure(.missing("No rules here.")) })
        scanner.acquire()
        defer { scanner.release() }
        XCTAssertEqual(scan(scanJob(try scannedFile("main-marker")), with: scanner)?.status, YaraScan.unavailable)
    }
}
