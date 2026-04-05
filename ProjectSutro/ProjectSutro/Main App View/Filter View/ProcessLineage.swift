//
//  ProcessLineage.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/17/25.
//

import Foundation
import SutroESFramework


/// Resolves and caches process lineage relationships for efficient filtering of Endpoint Security events.
///
/// This resolver builds an in-memory graph of process relationships from index entries, enabling
/// fast lookups of process trees. It tracks parent-child relationships through exec and fork events,
/// handling the nuance that exec events with the same PID represent process replacement rather than
/// new child processes.
///
/// ## Performance
/// - Initialization: O(n) where n is the number of index entries
/// - Lineage computation: O(m) where m is the size of the resulting tree
/// - Filtering checks: O(1) after pre-computing lineage sets
///
/// ## Implementation
/// - Exec events with matching PIDs are treated as process replacement, inheriting the parent
/// - Fork events create true parent-child relationships
/// - Cycle detection prevents infinite loops in malformed process trees
/// - Designed for single-use per filtering operation; instantiate fresh for each filter pass
public final class ProcessLineageResolver {
    private struct ProcessNode {
        let parentAuditToken: String
        let executablePathHash: UInt64
    }
    
    private var tokenToNodeCache: [String: ProcessNode] = [:]
    private var childrenCache: [String: Set<String>] = [:] // parent -> children
    
    public init(indexEntries: [EventIndexEntry], pathLookup: (UInt64) -> String?) {
        for entry in indexEntries {
            addToCache(
                token: entry.auditTokenString,
                parent: entry.parentAuditTokenString,
                pathHash: entry.executablePathHash
            )
            
            if let targetToken = entry.targetAuditTokenString {
                let isSamePidExec = isSamePidExec(entry: entry)
                let parentToken = isSamePidExec ?
                    entry.parentAuditTokenString :
                    entry.auditTokenString

                // Use 0 (unknown) for the child's path hash — the parent's hash is wrong for the
                // child. The child's own events will supply the correct hash via the update path
                // in addToCache.
                addToCache(
                    token: targetToken,
                    parent: parentToken,
                    pathHash: 0
                )
            }
        }
    }
    
    private func isSamePidExec(entry: EventIndexEntry) -> Bool {
        guard entry.esEventType == "ES_EVENT_TYPE_NOTIFY_EXEC" else { return false }
        return true
    }
    
    private func addToCache(token: String, parent: String, pathHash: UInt64) {
        if let existing = tokenToNodeCache[token] {
            // A fork/exec event pre-inserts a child token with pathHash = 0 (unknown at that point).
            // When the child's own events arrive, update the hash to the correct value.
            if existing.executablePathHash == 0 && pathHash != 0 {
                tokenToNodeCache[token] = ProcessNode(
                    parentAuditToken: existing.parentAuditToken,
                    executablePathHash: pathHash
                )
            }
        } else {
            tokenToNodeCache[token] = ProcessNode(
                parentAuditToken: parent,
                executablePathHash: pathHash
            )
            childrenCache[parent, default: []].insert(token)
        }
    }
    
    /// Pre-compute tokens in the lineage tree of a path
    /// - Parameters:
    ///   - includedPath: The executable path to match
    ///   - pathLookup: Function to resolve path hash to string
    ///   - includeAncestors: If true, includes parent processes (default: true)
    /// - Returns: Set of audit token strings that match the lineage criteria
    public func computeLineageSet(includedPath: String, pathLookup: (UInt64) -> String?, includeAncestors: Bool = true) -> Set<String> {
        var result = Set<String>()
        
        // Find all direct matches by path hash
        let matchingTokens = tokenToNodeCache.filter { node in
            guard let path = pathLookup(node.value.executablePathHash) else { return false }
            return path == includedPath
        }.map { $0.key }
        
        for token in matchingTokens {
            result.insert(token)
            
            // Add all ancestors if requested
            if includeAncestors {
                var current = token
                var visited = Set<String>()
                while let node = tokenToNodeCache[current], !visited.contains(current) {
                    result.insert(current)
                    visited.insert(current)
                    current = node.parentAuditToken
                }
            }
            
            // Always add descendants
            addDescendants(of: token, to: &result)
        }
        
        return result
    }
    
    private func addDescendants(of token: String, to result: inout Set<String>) {
        guard let children = childrenCache[token] else { return }
        
        for child in children {
            if !result.contains(child) {
                result.insert(child)
                addDescendants(of: child, to: &result)
            }
        }
    }
}
