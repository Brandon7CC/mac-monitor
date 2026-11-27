//
//  XProtectRules.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation
import OSLog


// MARK: - Apple's rules, ready to scan
/// Apple's rule sets loaded for scanning, from one XProtect bundle, and why any rule file couldn't be.
struct XProtectRules {
    /// The XProtect version the rules are from, such as `5377`.
    let version: String
    /// The rule sets that loaded.
    let sets: [XProtectRuleFile: YaraRuleSet]
    /// Why each rule file that didn't load couldn't be, as a sentence.
    let problems: [XProtectRuleFile: String]

    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "XProtectRules")

    /// Loads the rules: each rule file's compiled rules from the cache, or compiled in a child process and cached
    /// first. Blocks while a child compiles, which takes 0.1 to 0.3 s, so call it off the capture queues.
    ///
    /// - Parameters:
    ///   - sources: The rule files to load.
    ///   - library: This Mac's libyara.
    ///   - cache: Where compiled rules are kept.
    ///   - build: This macOS build, for the cache's keys.
    ///   - compile: Compiles a rule file's text into an open file and returns its warnings: in a child process
    ///     (``XProtectRuleCompiler``) unless a test gives another.
    /// - Returns: The rules.
    static func load(_ sources: XProtectRuleSources, library: YaraLibrary, cache: XProtectRuleCache,
                     build: String = XProtectRuleCache.currentBuild,
                     compile: (Data, Int32) throws -> [YaraDiagnostic]) -> XProtectRules {
        var sets: [XProtectRuleFile: YaraRuleSet] = [:]
        var problems: [XProtectRuleFile: String] = [:]
        for file in XProtectRuleFile.allCases {
            guard let text = sources.texts[file], let digest = sources.digest(of: file) else {
                problems[file] = "XProtect \(sources.version) has no \(file.rawValue)."
                continue
            }
            let key = XProtectRuleCache.key(for: file, digest: digest, abi: library.abi, build: build)
            if let cached = cache.load(file, key: key, library: library) {
                sets[file] = cached
                continue
            }
            do {
                try cache.store(for: file, key: key).write { descriptor in _ = try compile(text, descriptor) }
                cache.prune(file, keeping: key)
                guard let compiled = cache.load(file, key: key, library: library) else {
                    problems[file] = "The compiled \(file.rawValue) rules didn't load."
                    continue
                }
                sets[file] = compiled
            } catch {
                problems[file] = "\(file.rawValue) didn't compile: \(describe(error))."
                logger.error("\(file.rawValue, privacy: .public) didn't compile: \(describe(error), privacy: .public)")
            }
        }
        return XProtectRules(version: sources.version, sets: sets, problems: problems)
    }

    /// Why a compile failed, as words.
    ///
    /// - Parameter error: The error.
    /// - Returns: The reason.
    static func describe(_ error: Error) -> String {
        switch error {
        case XProtectRuleCompiler.Failure.notStarted(let code):
            return "the compiler couldn't start (\(String(cString: strerror(code))))"
        case XProtectRuleCompiler.Failure.timedOut:
            return "the compiler took too long"
        case XProtectRuleCompiler.Failure.ended(let status, let diagnostics):
            let first = diagnostics.first(where: \.isError).map { ": line \($0.line), \($0.message)" } ?? ""
            return "the compiler ended with status \(status)\(first)"
        default:
            return "\(error)"
        }
    }
}
