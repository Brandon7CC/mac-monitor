//
//  YaraLibrary.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation
import ObjectiveC


// MARK: - The libyara in XprotectFramework
/// The libyara XprotectFramework exports: its functions, resolved once, the layout they use (``YaraABI``), and Apple's
/// rule class, which names a match the way XProtect does.
///
/// Mac Monitor ships no YARA of its own. It uses the copy every Mac already has, so its rules compile and match exactly
/// as XProtect's own evaluation does on that macOS. Loading the framework runs no XProtect evaluation, logs nothing and
/// raises no Endpoint Security event.
///
/// **Threading:** the functions are safe to call from any thread, but a rule set scans on one thread at a time
/// (``YaraRuleSet``).
final class YaraLibrary: @unchecked Sendable {
    /// XprotectFramework, which links YARA and exports it.
    static let frameworkPath = "/System/Library/PrivateFrameworks/XprotectFramework.framework/XprotectFramework"

    /// The library this process loads, or why it can't, decided once.
    static let shared: Result<YaraLibrary, YaraUnavailable> = {
        do {
            return .success(try YaraLibrary())
        } catch let unavailable as YaraUnavailable {
            return .failure(unavailable)
        } catch {
            return .failure(.failed("\(error)"))
        }
    }()

    typealias CompilerCreate = @convention(c) (UnsafeMutablePointer<OpaquePointer?>) -> Int32
    typealias CompilerDestroy = @convention(c) (OpaquePointer) -> Void
    typealias CompilerSetCallback = @convention(c) (OpaquePointer, UnsafeRawPointer, UnsafeMutableRawPointer?) -> Void
    typealias CompilerSetIncludeCallback = @convention(c) (OpaquePointer, UnsafeRawPointer?, UnsafeRawPointer?,
                                                           UnsafeMutableRawPointer?) -> Void
    typealias CompilerAddString = @convention(c) (OpaquePointer, UnsafePointer<CChar>, UnsafePointer<CChar>?) -> Int32
    typealias CompilerGetRules = @convention(c) (OpaquePointer, UnsafeMutablePointer<OpaquePointer?>) -> Int32
    typealias RulesDestroy = @convention(c) (OpaquePointer) -> Int32
    typealias RulesSaveStream = @convention(c) (OpaquePointer, UnsafeMutableRawPointer) -> Int32
    typealias RulesLoadStream = @convention(c) (UnsafeMutableRawPointer, UnsafeMutablePointer<OpaquePointer?>) -> Int32
    typealias RulesScanMemory = @convention(c) (OpaquePointer, UnsafePointer<UInt8>?, Int, Int32, UnsafeRawPointer,
                                                UnsafeMutableRawPointer?, Int32) -> Int32

    /// The layout the functions use.
    let abi: YaraABI
    let compilerCreate: CompilerCreate
    let compilerDestroy: CompilerDestroy
    let compilerSetCallback: CompilerSetCallback
    let compilerSetIncludeCallback: CompilerSetIncludeCallback
    let compilerAddString: CompilerAddString
    let compilerGetRules: CompilerGetRules
    let rulesDestroy: RulesDestroy
    let rulesSaveStream: RulesSaveStream
    let rulesLoadStream: RulesLoadStream
    let rulesScanMemory: RulesScanMemory

    typealias Allocate = @convention(c) (UnsafeRawPointer, Selector) -> UnsafeMutableRawPointer?
    typealias InitFromYARA = @convention(c) (UnsafeMutableRawPointer, Selector, UnsafeRawPointer)
        -> UnsafeMutableRawPointer?

    /// Apple's rule class, and the two methods that make one from a matched `YR_RULE`.
    private let ruleClass: UnsafeRawPointer
    private let allocate: Allocate
    private let initFromYARA: InitFromYARA

    /// Loads XprotectFramework, resolves the functions, reads the layout and starts libyara.
    ///
    /// - Throws: ``YaraUnavailable`` when anything is missing, the layout is unknown, or libyara won't start.
    private init() throws {
        guard let handle = dlopen(Self.frameworkPath, RTLD_NOW | RTLD_LOCAL) else {
            throw YaraUnavailable.missing("XprotectFramework can't be loaded.")
        }
        func function<T>(_ name: String, as type: T.Type) throws -> T {
            guard let address = dlsym(handle, name) else {
                throw YaraUnavailable.missing("XprotectFramework has no \(name).")
            }
            return unsafeBitCast(address, to: type)
        }
        let initialize = try function("yr_initialize", as: (@convention(c) () -> Int32).self)
        compilerCreate = try function("yr_compiler_create", as: CompilerCreate.self)
        compilerDestroy = try function("yr_compiler_destroy", as: CompilerDestroy.self)
        compilerSetCallback = try function("yr_compiler_set_callback", as: CompilerSetCallback.self)
        compilerSetIncludeCallback = try function("yr_compiler_set_include_callback",
                                                  as: CompilerSetIncludeCallback.self)
        compilerAddString = try function("yr_compiler_add_string", as: CompilerAddString.self)
        compilerGetRules = try function("yr_compiler_get_rules", as: CompilerGetRules.self)
        rulesDestroy = try function("yr_rules_destroy", as: RulesDestroy.self)
        rulesSaveStream = try function("yr_rules_save_stream", as: RulesSaveStream.self)
        rulesLoadStream = try function("yr_rules_load_stream", as: RulesLoadStream.self)
        rulesScanMemory = try function("yr_rules_scan_mem", as: RulesScanMemory.self)

        let (abi, ruleClass): (YaraABI, AnyClass) = try Self.readLayout()
        self.abi = abi
        /// The class object itself, as Objective-C passes it. A metatype's bits aren't that pointer.
        self.ruleClass = UnsafeRawPointer(Unmanaged.passUnretained(ruleClass as AnyObject).toOpaque())
        guard let alloc = class_getClassMethod(ruleClass, NSSelectorFromString("alloc")),
              let make = class_getInstanceMethod(ruleClass, NSSelectorFromString("initFromYARA:")) else {
            throw YaraUnavailable.missing("Apple's rule class can't be made from a rule.")
        }
        allocate = unsafeBitCast(method_getImplementation(alloc), to: Allocate.self)
        initFromYARA = unsafeBitCast(method_getImplementation(make), to: InitFromYARA.self)
        guard initialize() == 0 else { throw YaraUnavailable.failed("libyara didn't start.") }
    }

    /// The layout, read from Apple's rule class and `XPMalwareEvaluation`.
    ///
    /// - Returns: The layout and the rule class it was read from.
    /// - Throws: ``YaraUnavailable`` when there's no rule class or the layout is unknown.
    private static func readLayout() throws -> (YaraABI, AnyClass) {
        guard let name = YaraABI.ruleClassNames.values.sorted().first(where: { NSClassFromString($0) != nil }),
              let ruleClass = NSClassFromString(name),
              let method = class_getInstanceMethod(ruleClass, NSSelectorFromString("initFromYARA:")),
              let argument = method_copyArgumentType(method, 2) else {
            throw YaraUnavailable.missing("XprotectFramework has no rule class Mac Monitor knows.")
        }
        defer { free(argument) }
        let rules = NSClassFromString("XPMalwareEvaluation")
            .flatMap { class_getInstanceVariable($0, "_rules") }
            .flatMap { ivar_getTypeEncoding($0) }
            .map { String(cString: $0) }
        let abi = try YaraABI.read(ruleEncoding: String(cString: argument), ruleClassName: name, rulesEncoding: rules)
        return (abi, ruleClass)
    }

    /// A matched rule's identifier, and what Apple's rule class says of it.
    ///
    /// - Parameter rule: A `YR_RULE` the scan callback was given, from a rule set still loaded.
    /// - Returns: The match.
    func match(of rule: UnsafeRawPointer) -> YaraMatch {
        let identifier = rule.load(fromByteOffset: abi.identifierOffset, as: UnsafePointer<CChar>?.self)
            .map { String(cString: $0) } ?? ""
        return autoreleasepool {
            let selectors = (alloc: NSSelectorFromString("alloc"), make: NSSelectorFromString("initFromYARA:"))
            guard let allocated = allocate(ruleClass, selectors.alloc),
                  let made = initFromYARA(allocated, selectors.make, rule),
                  let apple = Unmanaged<AnyObject>.fromOpaque(made).takeRetainedValue() as? NSObject else {
                return YaraMatch(identifier: identifier, name: nil, matchType: nil)
            }
            return YaraMatch(identifier: identifier, name: Self.read("ruleName", of: apple) as? String,
                             matchType: (Self.read("matchType", of: apple) as? NSNumber)?.intValue)
        }
    }

    /// A property of Apple's rule, only when the class has it: key-value coding raises on a missing key.
    ///
    /// - Parameters:
    ///   - key: The property.
    ///   - object: Apple's rule.
    /// - Returns: The value, or `nil`.
    private static func read(_ key: String, of object: NSObject) -> Any? {
        object.responds(to: NSSelectorFromString(key)) ? object.value(forKey: key) : nil
    }
}


// MARK: - A match
/// One rule that matched, named as XProtect names it.
struct YaraMatch: Equatable, Sendable {
    /// The rule's identifier, such as `XProtect_MACOS_OSASCRIPT_BOZO`.
    let identifier: String
    /// Apple's name for it, from its description, such as `MACOS.OSASCRIPT.BOZO`. `nil` for a rule without one.
    let name: String?
    /// Apple's match type: 11 for a rule XProtect acts on, 0 for one it only reports (`match_type = 4`).
    let matchType: Int?

    /// Does XProtect only report this rule, never act on it (`match_type = 4`)? Apple's hunting rules are these.
    var isReportOnly: Bool { matchType == 0 }
}
