//
//  ProcessLineage+Seeding.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Processes no event created
extension ProcessLineage {
    /// Add the processes that were running before the table was told of anything. What an event has already said
    /// of a process stands: only a process that's missing, or known by its key alone, is filled in. A process whose
    /// pid the table knows a newer program of is left out: it exec'd since the list was read.
    ///
    /// - Parameter running: Each running process's program and its parent's pid.
    public func seed(_ running: [(program: ProcessProgram, parent: Int32)]) {
        lock.withLock {
            var seeded: [(node: Node, parent: Int32)] = []
            for (program, parent) in running where !program.key.isRoot {
                if let known = nodes[program.key] {
                    guard !known.program.isKnown else { continue }
                    known.program = program
                    seeded.append((known, parent))
                } else if (newest[program.key.pid]?.program.key.pidversion ?? -1) < program.key.pidversion {
                    let node = Node(program, parent: nil)
                    keep(node)
                    seeded.append((node, parent))
                }
            }
            for (node, parent) in seeded where node.parent == nil && parent > ProcessKey.launchd {
                node.parent = newest[parent]
            }
        }
    }

    /// Take in a process as a trace describes it (``ProcessSnapshot``): one that was running before the capture
    /// started, or whose exec the trace doesn't hold. What an event has already said of a process stands: its
    /// program is filled in only when it's missing or known by its key alone, and each process named is given the
    /// next as its parent only where it has none.
    ///
    /// - Parameters:
    ///   - program: The process's program.
    ///   - ancestors: Its ancestors' keys, nearest first.
    public func describe(_ program: ProcessProgram, ancestors: [ProcessKey]) {
        lock.withLock {
            guard !program.key.isRoot else { return }
            var child: Node
            if let known = nodes[program.key] {
                if !known.program.isKnown { known.program = program }
                child = known
            } else {
                child = Node(program, parent: nil)
                keep(child)
            }
            for key in ancestors where !key.isRoot {
                let parent = node(key)
                if child.parent == nil, parent !== child { child.parent = parent }
                child = parent
            }
        }
    }
}
