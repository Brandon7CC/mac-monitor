//
//  JSONSchema+Checking.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os


// MARK: - Checking
extension JSONSchema {
    /// Check a value against one of the schema's nodes.
    ///
    /// Every keyword applies as JSON Schema 2020-12 says, `$ref` beside its siblings. A value of the wrong type is
    /// reported once, without checking further into it. An unexpected key directly under the record's `event` is an
    /// event of a type Mac Monitor doesn't record.
    ///
    /// In ``TelemetryValidator/Mode/eslogger`` mode Mac Monitor's own keys aren't required, and one that's present is
    /// an issue rather than checked.
    ///
    /// - Parameters:
    ///   - value: A `JSONSerialization` value.
    ///   - node: The node.
    ///   - path: Where the value is in its record.
    ///   - context: The record's line, the mode, and the coverage recorder, if any.
    ///   - issues: Receives the issues found.
    /// - Returns: `true` if the value matches.
    func check(_ value: Any, against node: JSONSchemaNode, at path: InstancePath, in context: CheckContext,
               into issues: inout FoundIssues) -> Bool {
        /// Report a problem with this value.
        func report(_ problem: TelemetryIssue.Problem) {
            issues.add(line: context.line, path: path, schemaLocation: node.location, problem: problem, value: value)
        }
        guard let type = JSONType(of: value) else {
            let allowed = (node.types ?? JSONType.allCases).map(\.rawValue)
            report(.type(expected: allowed, found: "\(Swift.type(of: value))"))
            return false
        }
        if let types = node.types, !type.satisfies(types) {
            report(.type(expected: types.map(\.rawValue), found: type.rawValue))
            return false
        }
        let before = issues.count
        if node.constant != nil || node.values != nil {
            let scalar = JSONScalar(value, of: type)
            if let constant = node.constant, scalar != constant { report(.notConst(constant.description)) }
            if let values = node.values, !(scalar.map(values.contains) ?? false) { report(.notInEnum) }
        }
        if let pattern = node.pattern, type == .string, let text = value as? String, !pattern.isFound(in: text) {
            report(.pattern(pattern.text))
        }
        if type == .object, let object = (value as AnyObject) as? NSDictionary {
            checkObject(object, against: node, at: path, in: context, into: &issues)
        }
        if let items = node.items, type == .array, let array = (value as AnyObject) as? NSArray {
            for (index, element) in array.enumerated() {
                _ = check(element, against: items, at: .index(path, index), in: context, into: &issues)
            }
        }
        if !node.anyOf.isEmpty { checkBranches(value, type: type, of: node, at: path, in: context, into: &issues) }
        if let name = node.reference, let definition = definitions[name] {
            _ = check(value, against: definition, at: path, in: context, into: &issues)
        }
        guard issues.count == before else { return false }
        context.coverage?.observe(type, at: node.location)
        return true
    }
    
    /// Check an object's keys: their count, the required ones, each key's schema, and the keys the schema doesn't have.
    ///
    /// - Parameters:
    ///   - object: The object.
    ///   - node: Its schema.
    ///   - path: Where it is in its record.
    ///   - context: The record's line, the mode, and the coverage recorder, if any.
    ///   - issues: Receives the issues found.
    private func checkObject(_ object: NSDictionary, against node: JSONSchemaNode, at path: InstancePath,
                             in context: CheckContext, into issues: inout FoundIssues) {
        let tooFew = node.minProperties.map { object.count < $0 } ?? false
        if tooFew || (node.maxProperties.map { object.count > $0 } ?? false) {
            issues.add(line: context.line, path: path, schemaLocation: node.location,
                       problem: .propertyCount(found: object.count, minimum: node.minProperties,
                                               maximum: node.maxProperties))
        }
        var known = 0
        for name in node.propertyNames {
            let schema = node.properties[name]!, place = InstancePath.key(path, name)
            let foreign = context.mode == .eslogger && schema.origin == .macMonitor
            guard let child = object[name] else {
                /// In eslogger mode a Mac Monitor key is never required, and leaving it out covers nothing.
                if foreign { continue }
                if node.required.contains(name) {
                    issues.add(line: context.line, path: place, schemaLocation: schema.location, problem: .missing)
                } else {
                    context.coverage?.absent(name, in: node.location)
                }
                continue
            }
            known += 1
            if foreign {
                issues.add(line: context.line, path: place, schemaLocation: schema.location,
                           problem: .macMonitorFieldInESLogger)
            } else {
                _ = check(child, against: schema, at: place, in: context, into: &issues)
            }
        }
        for name in node.unspecifiedRequired where object[name] == nil {
            issues.add(line: context.line, path: .key(path, name), schemaLocation: node.location, problem: .missing)
        }
        guard node.closed, object.count > known else { return }
        let extra = object.allKeys.compactMap { $0 as? String }.filter { node.properties[$0] == nil }.sorted()
        for name in extra {
            let problem: TelemetryIssue.Problem = path == .key(.root, "event")
                ? .unsupportedEvent(JSONText.cut(name)) : .unexpected
            issues.add(line: context.line, path: .key(path, name), schemaLocation: node.location, problem: problem)
        }
    }
    
    /// Check a value against a node's `anyOf`, stopping at the first alternative it matches.
    ///
    /// When it matches none, the issues reported are those of the alternative that allows the value's type (the one
    /// with the fewest, if several do), looking through one `$ref`: a broken object reports what's wrong inside it.
    /// When no alternative allows its type, the issue lists the types they do allow. An alternative that doesn't
    /// allow the value's type can't match, so it isn't checked: no issue is made only to be thrown away.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - type: Its JSON type.
    ///   - node: The node with the `anyOf`.
    ///   - path: Where the value is in its record.
    ///   - context: The record's line, the mode, and the coverage recorder, if any.
    ///   - issues: Receives the issues found.
    private func checkBranches(_ value: Any, type: JSONType, of node: JSONSchemaNode, at path: InstancePath,
                               in context: CheckContext, into issues: inout FoundIssues) {
        var candidates: [FoundIssues] = [], allowed: [String] = []
        for (index, branch) in node.anyOf.enumerated() {
            let types = branch.types ?? branch.reference.flatMap { definitions[$0]?.types }
            for name in (types ?? []).map(\.rawValue) where !allowed.contains(name) { allowed.append(name) }
            guard types.map(type.satisfies) ?? true else { continue }
            var found = FoundIssues(limit: issues.limit)
            if check(value, against: branch, at: path, in: context.uncovered, into: &found) {
                /// Checked again to record what it covers: a branch that failed covers nothing.
                if let coverage = context.coverage {
                    _ = check(value, against: branch, at: path, in: context, into: &found)
                    coverage.match(branch: index, at: node.location)
                }
                return
            }
            candidates.append(found)
        }
        if let closest = candidates.min(by: { $0.count < $1.count }) {
            issues.add(contentsOf: closest)
        } else {
            issues.add(line: context.line, path: path, schemaLocation: node.location,
                       problem: .noBranch(expected: allowed, found: type.rawValue), value: value)
        }
    }
}


// MARK: - Check context
/// What a check knows about the record it's checking.
struct CheckContext {
    /// The line the record starts on in its trace, or `nil` for a record checked on its own.
    let line: Int?
    /// Which keys are checked.
    let mode: TelemetryValidator.Mode
    /// Records what the check exercises, for the tests.
    let coverage: CoverageRecorder?
    
    /// This context without its coverage recorder: for alternatives that may not match.
    var uncovered: CheckContext { CheckContext(line: line, mode: mode, coverage: nil) }
}


// MARK: - Coverage
/// Records which parts of a schema a set of records exercises, so the tests can require every part of it to be used:
/// a part no record exercises is stale or dead.
final class CoverageRecorder: @unchecked Sendable {
    /// What has been recorded.
    struct Observations {
        /// Each schema location that matched a value, with the JSON types of the values it matched.
        var types: [String: Set<JSONType>] = [:]
        /// Each `anyOf`'s location, with the alternatives that matched.
        var branches: [String: Set<Int>] = [:]
        /// Each object schema's location, with the keys it doesn't require that an object left out.
        var absences: [String: Set<String>] = [:]
    }
    
    /// What has been recorded, behind a lock so records can be checked in parallel.
    private let state = OSAllocatedUnfairLock(initialState: Observations())
    
    /// What has been recorded so far.
    var observations: Observations { state.withLock { $0 } }
    
    /// Record that a schema location matched a value.
    ///
    /// - Parameters:
    ///   - type: The value's JSON type.
    ///   - location: The schema location.
    func observe(_ type: JSONType, at location: String) {
        state.withLock { _ = $0.types[location, default: []].insert(type) }
    }
    
    /// Record that an alternative of an `anyOf` matched.
    ///
    /// - Parameters:
    ///   - branch: The alternative's index.
    ///   - location: The `anyOf`'s schema location.
    func match(branch: Int, at location: String) {
        state.withLock { _ = $0.branches[location, default: []].insert(branch) }
    }
    
    /// Record that an object left out a key its schema doesn't require.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - location: The object's schema location.
    func absent(_ key: String, in location: String) {
        state.withLock { _ = $0.absences[location, default: []].insert(key) }
    }
}
