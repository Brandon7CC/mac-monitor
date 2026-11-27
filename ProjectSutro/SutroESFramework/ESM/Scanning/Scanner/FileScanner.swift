//
//  FileScanner.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation
import OSLog


// MARK: - The scanner
/// Scans written files and the scripts execs run with Apple's XProtect rules for the capture sessions that scan
/// (Security Extension context).
///
/// Capture sessions share one (``shared``). It loads Apple's rules when the first session acquires it, from the
/// compiled cache or compiled in a child process (``XProtectRules``), and drops them when the last releases it, so
/// nothing is loaded while nobody scans. On macOS 13 the rules also go after a minute without a scan, since there the
/// memory comes back, and load again from the cache in about 25 ms. On later releases freed rule memory isn't given
/// back, so they stay loaded while anyone scans.
///
/// A file is asked for once per version (``FileScanVersion``): a second request while the first is queued waits for
/// the same scan, and one after it gets the remembered result, so the file lanes of several sessions, the rename that
/// moves a file after its close, and the execs that run a script scanned at its close, cost one scan. A result answers
/// a request for the rule files that ran, or fewer (``FileScanMemory``). An exec looks its script up ignoring the
/// change time, and hands over the bytes it read when it read all of them (``Job``). Each scan is admitted by the CPU
/// budget (``FileScanBudget``), runs on one serial queue, and is charged its thread's CPU time.
///
/// **Threading:** thread-safe. Answers are delivered on the scan queue.
public final class FileScanner: @unchecked Sendable {
    /// The one the Security Extension's capture sessions share.
    public static let shared = FileScanner()

    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "FileScanner")

    /// The largest file scanned. 32 MB takes about 160 to 220 ms on the VMs.
    let maxBytes: Int
    /// The most seconds libyara may spend on one rule set.
    let timeout: Int32
    /// How long the rules stay loaded without a scan where unloading gives memory back (YARA 3, macOS 13).
    let idleUnload: TimeInterval
    /// How often a loaded rule set's XProtect version is checked for an update.
    let updateCheck: TimeInterval
    /// Loads the rules.
    private let load: () -> Result<XProtectRules, YaraUnavailable>
    /// Reads the XProtect version the rules would load from now, to notice an update.
    private let currentVersion: () -> String?
    /// The generation of this Mac's libyara, which decides whether idle rules are unloaded.
    private let generation: YaraABI.Generation?
    private let clock: () -> TimeInterval
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.file-scanner", qos: .utility)

    /// Only touched under ``lock``.
    private struct State {
        var users = 0
        var budget: FileScanBudget
        /// Scans queued or running, by version, and who waits for each.
        var waiting: [FileScanVersion: [Pending]] = [:]
        /// Recent results.
        var remembered: FileScanMemory
        /// Bumped by each acquire from none and each release to none, so a stale unload does nothing.
        var epoch = 0
        /// When the last scan finished.
        var lastScan: TimeInterval = 0

        /// Wait for a scan of a version already queued that runs the rule files asked for, or more.
        ///
        /// - Parameters:
        ///   - version: The version.
        ///   - files: The rule files asked for. Empty waits for any.
        ///   - answer: Called with its result.
        /// - Returns: Whether such a scan is queued.
        mutating func join(_ version: FileScanVersion, covering files: Set<XProtectRuleFile>,
                           _ answer: @escaping (YaraScan) -> Void) -> Bool {
            guard let index = waiting[version]?.firstIndex(where: { $0.files.isSuperset(of: files) }) else {
                return false
            }
            waiting[version]?[index].answers.append(answer)
            return true
        }

        /// A queued scan is done: stop waiting for it.
        ///
        /// - Parameters:
        ///   - version: Its version.
        ///   - files: The rule files its job asked for.
        /// - Returns: Who waited for it.
        mutating func finish(_ version: FileScanVersion, files: Set<XProtectRuleFile>) -> [(YaraScan) -> Void] {
            guard var pending = waiting[version], let index = pending.firstIndex(where: { $0.files == files }) else {
                return []
            }
            let answers = pending.remove(at: index).answers
            waiting[version] = pending.isEmpty ? nil : pending
            return answers
        }
    }
    private let lock = NSLock()
    private var state: State
    /// The loaded rules, or why there are none. Only touched on ``queue``.
    private var rules: Result<XProtectRules, YaraUnavailable>?
    /// When the loaded rules' version was last checked. Only touched on ``queue``.
    private var checked: TimeInterval = 0

    /// - Parameters:
    ///   - maxBytes: The largest file scanned.
    ///   - timeout: The most seconds libyara may spend on one rule set.
    ///   - idleUnload: How long rules stay loaded without a scan, where unloading gives memory back.
    ///   - updateCheck: How often the loaded XProtect version is checked for an update.
    ///   - budget: The CPU budget.
    ///   - memory: How many results to remember.
    ///   - generation: The libyara generation, or `nil` when there's none.
    ///   - currentVersion: Reads the XProtect version rules would load from now.
    ///   - clock: The clock, seconds since boot unless a test gives another.
    ///   - load: Loads the rules, on the scan queue.
    init(maxBytes: Int = 32 << 20, timeout: Int32 = 2, idleUnload: TimeInterval = 60, updateCheck: TimeInterval = 900,
         budget: FileScanBudget = FileScanBudget(), memory: Int = 1024,
         generation: YaraABI.Generation? = (try? YaraLibrary.shared.get())?.abi.generation,
         currentVersion: @escaping () -> String? = { XProtectRuleSources.read()?.version },
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         load: @escaping () -> Result<XProtectRules, YaraUnavailable> = FileScanner.loadInstalledRules) {
        self.maxBytes = maxBytes
        self.timeout = timeout
        self.idleUnload = idleUnload
        self.updateCheck = updateCheck
        self.generation = generation
        self.currentVersion = currentVersion
        self.clock = clock
        self.load = load
        state = State(budget: budget, remembered: FileScanMemory(capacity: memory))
    }

    /// Loads this Mac's rules, compiling in a child process when the cache has none.
    ///
    /// - Returns: The rules, or why there are none.
    static func loadInstalledRules() -> Result<XProtectRules, YaraUnavailable> {
        YaraLibrary.shared.flatMap { library in
            guard let sources = XProtectRuleSources.read() else {
                return .failure(.missing("This Mac has no XProtect rules."))
            }
            guard let executable = Bundle.main.executablePath else {
                return .failure(.missing("The Security Extension's executable can't be found."))
            }
            let rules = XProtectRules.load(sources, library: library, cache: XProtectRuleCache()) { text, output in
                try XProtectRuleCompiler.compile(text, into: output, executable: executable)
            }
            guard !rules.sets.isEmpty else {
                return .failure(.failed(rules.problems.values.sorted().first ?? "No XProtect rules loaded."))
            }
            return .success(rules)
        }
    }

    // MARK: Users

    /// A session starts scanning. The first loads the rules, in the background.
    public func acquire() {
        let first = lock.withLock { () -> Bool in
            state.users += 1
            guard state.users == 1 else { return false }
            state.epoch += 1
            return true
        }
        if first { queue.async { self.loadRules() } }
    }

    /// A session stops scanning. The last drops the rules and what it remembered.
    public func release() {
        let last = lock.withLock { () -> Bool in
            guard state.users > 0 else { return false }
            state.users -= 1
            guard state.users == 0 else { return false }
            state.epoch += 1
            state.remembered.removeAll()
            return true
        }
        if last { queue.async { self.rules = nil } }
    }

    /// Is any session scanning?
    var isInUse: Bool { lock.withLock { state.users > 0 } }

    // MARK: Scanning

    /// Ask for a file's scan. A close's forgets what an earlier version with the same content said, for execs
    /// (``FileScanMemory/forgetContent(changedBy:)``).
    ///
    /// - Parameters:
    ///   - job: The file.
    ///   - answer: Called on the scan queue with the result, only when this returns ``Submission/queued``.
    /// - Returns: The result now, or that it's queued.
    func submit(_ job: Job, answer: @escaping (YaraScan) -> Void) -> Submission {
        let size = job.size
        return lock.withLock { () -> Submission in
            guard state.users > 0 else { return .answered(.notScanned(YaraScan.unavailable)) }
            if !job.anyChangeTime { state.remembered.forgetContent(changedBy: job.version) }
            if let known = state.remembered.result(for: job.version, covering: job.files,
                                                   anyChangeTime: job.anyChangeTime) {
                return .answered(known)
            }
            if state.join(job.version, covering: job.files, answer) { return .queued }
            if case .unread = job.source { return .answered(.notScanned(YaraScan.unreadable)) }
            guard size <= maxBytes else { return .answered(.notScanned(YaraScan.tooLarge)) }
            switch state.budget.admit(bytes: size) {
            case .overBudget: return .answered(.notScanned(YaraScan.overBudget))
            case .busy: return .answered(.notScanned(YaraScan.busy))
            case .admit(let cost):
                state.waiting[job.version, default: []].append(Pending(files: job.files, answers: [answer]))
                queue.async { self.run(job, expected: cost) }
                return .queued
            }
        }
    }

    /// A modified close of a file that isn't scanned forgets what an earlier version with the same content said, for
    /// execs (``FileScanMemory/forgetContent(changedBy:)``). A close that's scanned forgets as it's submitted.
    ///
    /// - Parameter version: The version the close names.
    func forgetContent(changedBy version: FileScanVersion) {
        lock.withLock { state.remembered.forgetContent(changedBy: version) }
    }

    /// The answer for a version a close asked for, for the rename that moves the file: remembered, or the queued
    /// scan's once it's done. Nothing is scanned for it.
    ///
    /// - Parameters:
    ///   - version: The version, from the rename's stat of its source.
    ///   - answer: Called on the scan queue with the result, only when this returns ``Submission/queued``.
    /// - Returns: The result now, that it's queued, or `nil` when no close asked for that version.
    func follow(_ version: FileScanVersion, answer: @escaping (YaraScan) -> Void) -> Submission? {
        lock.withLock { () -> Submission? in
            guard state.users > 0 else { return nil }
            if let known = state.remembered.result(for: version) { return .answered(known) }
            return state.join(version, covering: [], answer) ? .queued : nil
        }
    }

    /// Scan one file on the queue, charge it, remember it, and answer everyone waiting for it. A scan queued before
    /// it that ran its rule files, or more, answers it without a scan of its own, looked up as ``submit(_:answer:)``
    /// looks: an exec's by its content, and only with a result that describes it.
    ///
    /// - Parameters:
    ///   - job: The file.
    ///   - expected: The cost it was admitted at.
    private func run(_ job: Job, expected: Double) {
        let known = lock.withLock {
            state.remembered.result(for: job.version, covering: job.files, anyChangeTime: job.anyChangeTime)
        }
        let start = Self.threadCPUTime()
        let (result, bytes, files) = known.map { ($0, 0, job.files) } ?? scan(job)
        let spent = Self.threadCPUTime() - start
        let (waiters, epoch) = lock.withLock { () -> ([(YaraScan) -> Void], Int) in
            state.budget.charge(expected: expected, spent: spent, bytes: bytes)
            let waiters = state.finish(job.version, files: job.files)
            if state.users > 0, known == nil { state.remembered.remember(result, files: files, for: job.version) }
            state.lastScan = clock()
            return (waiters, state.epoch)
        }
        waiters.forEach { $0(result) }
        scheduleIdleUnload(epoch: epoch)
    }

    /// Read a file, or take the bytes read already, and scan it with the rule sets that apply.
    ///
    /// - Parameter job: The file.
    /// - Returns: The result, the bytes scanned, and the rule files that ran.
    private func scan(_ job: Job) -> (YaraScan, Int, Set<XProtectRuleFile>) {
        guard case .success(let loaded) = currentRules() else {
            return (.notScanned(YaraScan.unavailable), 0, job.files)
        }
        switch job.source {
        case .bytes(let bytes):
            return bytes.withUnsafeBytes { scan($0, files: job.files, with: loaded) }
        case .file(let path, let info, let reader):
            switch FileScanReader.read(path, stat: info, for: reader, maxBytes: maxBytes) {
            case .bytes(let buffer): return scan(buffer.bytes, files: job.files, with: loaded)
            case .notRead(let reason): return (.notScanned(reason, xprotectVersion: loaded.version), 0, job.files)
            }
        case .unread:
            return (.notScanned(YaraScan.unreadable, xprotectVersion: loaded.version), 0, job.files)
        }
    }

    /// Scan a file's bytes with the rule sets that apply to them.
    ///
    /// - Parameters:
    ///   - bytes: The file's bytes.
    ///   - asked: The rule files its job asked for.
    ///   - loaded: The rules.
    /// - Returns: The result, the bytes scanned, and the rule files that ran.
    private func scan(_ bytes: UnsafeRawBufferPointer, files asked: Set<XProtectRuleFile>,
                      with loaded: XProtectRules) -> (YaraScan, Int, Set<XProtectRuleFile>) {
        var matches: [YaraMatch] = []
        let files = FileScanKind.ruleFiles(asked, reading: bytes)
        for file in XProtectRuleFile.allCases where files.contains(file) {
            guard let set = loaded.sets[file] else { continue }
            switch set.scan(bytes, timeout: timeout) {
            case .matched(let found): matches += found
            case .failed(.timedOut): return (.notScanned(YaraScan.timedOut, xprotectVersion: loaded.version), 0, files)
            case .failed(.tooManyMatches):
                return (.notScanned(YaraScan.tooManyMatches, xprotectVersion: loaded.version), bytes.count, files)
            case .failed(.error(let code)):
                Self.logger.error("A scan failed with libyara error \(code, privacy: .public).")
                return (.notScanned(YaraScan.unavailable, xprotectVersion: loaded.version), 0, files)
            }
        }
        let result = YaraScan(status: YaraScan.scanned, xprotectVersion: loaded.version, matches: matches)
        return (result, bytes.count, files)
    }

    // MARK: Rules

    /// The rules, loaded first if they aren't, and loaded again when XProtect has updated. Call on the queue.
    ///
    /// - Returns: The rules, or why there are none.
    private func currentRules() -> Result<XProtectRules, YaraUnavailable> {
        if case .success(let loaded)? = rules, clock() - checked >= updateCheck {
            checked = clock()
            if let version = currentVersion(), version != loaded.version {
                Self.logger.log(
                    "XProtect updated from \(loaded.version, privacy: .public) to \(version, privacy: .public).")
                rules = nil
            }
        }
        if rules == nil { loadRules() }
        return rules ?? .failure(.failed("No XProtect rules loaded."))
    }

    /// Load the rules unless they are. Call on the queue.
    private func loadRules() {
        guard rules == nil, isInUse else { return }
        let loaded = load()
        checked = clock()
        if case .failure(let reason) = loaded {
            Self.logger.error("Apple's XProtect rules can't be used: \(reason.description, privacy: .public)")
        }
        rules = loaded
    }

    /// After a quiet minute, drop the rules where that gives memory back (YARA 3). A later scan loads them again.
    ///
    /// - Parameter epoch: The users' epoch when the scan finished. A release or acquire since cancels it.
    private func scheduleIdleUnload(epoch: Int) {
        guard generation == .yara3 else { return }
        queue.asyncAfter(deadline: .now() + idleUnload) { [weak self] in
            guard let self else { return }
            let idle = self.lock.withLock {
                self.state.epoch == epoch && self.state.waiting.isEmpty
                    && self.clock() - self.state.lastScan >= self.idleUnload
            }
            if idle { self.rules = nil }
        }
    }

    /// Whether the rules are loaded now, for Settings. Nothing is loaded to answer.
    ///
    /// - Parameter answer: Called on the scan queue, once the scans queued before it are done.
    func status(_ answer: @escaping (XProtectRuleStatus) -> Void) {
        queue.async { [self] in
            switch rules {
            case .success(let loaded)?:
                answer(XProtectRuleStatus(state: .loaded, version: loaded.version,
                                          problems: loaded.problems.values.sorted()))
            case .failure(let reason)?: answer(XProtectRuleStatus(state: .failed, problems: [reason.description]))
            case nil: answer(XProtectRuleStatus(state: .unloaded))
            }
        }
    }

    /// Wait for everything queued so far, such as before a test reads what happened.
    func drain() {
        queue.sync {}
    }

    /// Are rules loaded now? For tests.
    var hasRulesLoaded: Bool { queue.sync { if case .success? = rules { return true } else { return false } } }

    /// This thread's CPU time, in seconds.
    ///
    /// - Returns: User and system time.
    static func threadCPUTime() -> Double {
        var time = timespec()
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time)
        return Double(time.tv_sec) + Double(time.tv_nsec) / 1e9
    }
}
