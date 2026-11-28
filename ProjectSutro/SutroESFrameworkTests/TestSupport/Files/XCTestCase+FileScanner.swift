//
//  XCTestCase+FileScanner.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A scanner with stand-in rules
/// How many times a scanner loaded its rules.
final class ScannerLoads: @unchecked Sendable {
    var count = 0
}


extension XCTestCase {
    /// This Mac's libyara, or the test is skipped.
    ///
    /// - Returns: The library.
    /// - Throws: `XCTSkip` without one.
    func scannerLibrary() throws -> YaraLibrary {
        guard case .success(let library) = YaraLibrary.shared else { throw XCTSkip("No libyara here.") }
        return library
    }

    /// Stand-in rules: `Main` finds "main-marker" and `Hunt` "hunt-marker" (reported only) in XProtect.yara, and
    /// `Script` finds "script-marker" in XPScripts.yr.
    ///
    /// - Returns: The rules, as XProtect 5377's.
    /// - Throws: `XCTSkip` without libyara, or a failure when they don't compile.
    func standInRules() throws -> XProtectRules {
        let library = try scannerLibrary()
        let main = try XCTUnwrap(YaraCompiler.compile("""
        rule Main { meta: description = "TEST.MAIN" strings: $a = "main-marker" condition: $a }
        rule Hunt { meta: description = "HUNT.TEST" match_type = 4 strings: $a = "hunt-marker" condition: $a }
        """, with: library).rules)
        let scripts = try XCTUnwrap(YaraCompiler.compile(
            "rule Script { strings: $a = \"script-marker\" condition: $a }", with: library).rules)
        return XProtectRules(version: "5377", sets: [.xprotect: main, .scripts: scripts], problems: [:])
    }

    /// A scanner with the stand-in rules (``standInRules()``).
    ///
    /// - Parameters:
    ///   - budget: Its CPU budget.
    ///   - maxBytes: The largest file it scans.
    ///   - generation: The libyara generation it acts as.
    ///   - idleUnload: How long rules stay loaded without a scan, on YARA 3.
    ///   - loads: Counts its loads.
    ///   - gate: Holds its first load, and so every scan behind it, until signalled.
    /// - Returns: The scanner.
    /// - Throws: `XCTSkip` without libyara.
    func makeScanner(budget: FileScanBudget = FileScanBudget(), maxBytes: Int = 32 << 20,
                     generation: YaraABI.Generation = .yara4, idleUnload: TimeInterval = 60,
                     loads: ScannerLoads = ScannerLoads(), gate: DispatchSemaphore? = nil) throws -> FileScanner {
        let rules = try standInRules()
        return FileScanner(maxBytes: maxBytes, idleUnload: idleUnload, budget: budget, generation: generation,
                           currentVersion: { "5377" }, load: {
            gate?.wait()
            loads.count += 1
            return .success(rules)
        })
    }

    /// Writes a file and returns its path and stat, as an event would carry them: the real path, since Endpoint
    /// Security's paths have no symbolic link and the scanner refuses one (`/var` is one).
    ///
    /// - Parameters:
    ///   - text: What it holds.
    ///   - name: Its name, in a folder of its own.
    /// - Returns: Its path and stat.
    /// - Throws: The error writing it.
    func scannedFile(_ text: String, name: String = "file") throws -> (path: String, info: stat) {
        let path = try temporaryFile(bytes: Array(text.utf8), named: name)
        return (path, try fileStat(path))
    }

    /// Writes a file again with text of the same size and puts its old modification time back, as `touch -r` does,
    /// so only its change time tells the two versions apart.
    ///
    /// - Parameters:
    ///   - file: The file's path and stat.
    ///   - text: What it holds now, as many bytes as it held.
    /// - Returns: Its stat now.
    /// - Throws: The error writing it.
    func rewrite(_ file: (path: String, info: stat), with text: String) throws -> stat {
        Thread.sleep(forTimeInterval: 0.01)
        try Data(text.utf8).write(to: URL(fileURLWithPath: file.path))
        var times = [timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)), file.info.st_mtimespec]
        XCTAssertEqual(utimensat(AT_FDCWD, file.path, &times, 0), 0)
        let rewritten = try fileStat(file.path)
        XCTAssertEqual(FileScanVersion(rewritten).content, FileScanVersion(file.info).content)
        XCTAssertNotEqual(FileScanVersion(rewritten), FileScanVersion(file.info), "The rewrite changed the ctime.")
        return rewritten
    }

    /// A close's job for a file, read for the user running the test.
    ///
    /// - Parameters:
    ///   - file: The file's path and stat.
    ///   - files: The rule files its type gets.
    /// - Returns: The job.
    func scanJob(_ file: (path: String, info: stat),
                 files: Set<XProtectRuleFile> = [.xprotect]) -> FileScanner.Job {
        FileScanner.Job(path: file.path, info: file.info, reader: FileReader(uid: getuid(), gid: getgid()),
                        files: files)
    }

    /// Submits a job and waits for its answer, however it comes.
    ///
    /// - Parameters:
    ///   - job: The job.
    ///   - scanner: The scanner.
    /// - Returns: The answer, or `nil` when none came in 10 seconds.
    func scan(_ job: FileScanner.Job, with scanner: FileScanner) -> YaraScan? {
        let answered = expectation(description: "answered")
        let result = Recorded<YaraScan>()
        switch scanner.submit(job, answer: { result.append($0); answered.fulfill() }) {
        case .answered(let now):
            result.append(now)
            answered.fulfill()
        case .queued:
            break
        }
        wait(for: [answered], timeout: 10)
        return result.all.first
    }
}
