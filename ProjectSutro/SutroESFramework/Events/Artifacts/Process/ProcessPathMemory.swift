//
//  ProcessPathMemory.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Process path memory
/// The executables of the processes a stream of events has named, by audit token, for naming launched-by parents.
///
/// A token's pid and pid version name one process image (the version changes with each exec), whose executable never
/// changes: a path remembered for a token is exact, where a path read by pid alone can belong to whatever process
/// reused the pid. A capture lane remembers the parents its execs and forks name, and what it reads for others; a
/// trace import remembers every process the trace names, and reads nothing.
///
/// Bounded like ``RowCache``: two generations of up to ``capacity`` processes each. When the newer one fills up the
/// older one is dropped, and a process found in the older one moves to the newer one, so busy parents (shells, Finder,
/// launchd's jobs) stay. Forgetting a process only costs its path.
///
/// Not thread-safe: each capture lane keeps its own (used under its gate), and each trace import its own.
final class ProcessPathMemory {
    /// The processes a capture lane's memory holds per generation.
    static let laneCapacity = 4_096
    /// The processes a trace import's memory holds per generation.
    static let traceCapacity = 65_536
    
    /// A process image: its pid and pid version.
    private struct Image: Hashable {
        let pid, pidversion: Int32
        
        /// - Parameter token: The image's audit token.
        init(_ token: AuditToken) {
            (pid, pidversion) = (token.pid, token.pidversion)
        }
    }
    
    /// The newer and the older generation.
    private var recent: [Image: String] = [:], older: [Image: String] = [:]
    /// The process remembered last, while it's in the newer generation: a trace's events come in runs of one process.
    private var last: Image?
    /// The processes each generation holds.
    let capacity: Int
    
    /// - Parameter capacity: The processes each generation holds.
    init(capacity: Int) {
        self.capacity = capacity
    }
    
    /// The executable of a process remembered before.
    ///
    /// - Parameter token: The process's audit token.
    /// - Returns: Its path, or `nil` if it isn't remembered (or there's no token).
    func path(of token: AuditToken?) -> String? {
        guard let token else { return nil }
        let image = Image(token)
        if let path = recent[image] { return path }
        guard let path = older.removeValue(forKey: image) else { return nil }
        store(path, for: image)
        return path
    }
    
    /// The executable of a process: remembered, or else read and remembered under its token.
    ///
    /// - Parameters:
    ///   - pid: The process's pid.
    ///   - token: Its audit token, when known. Without one, the path is read and not remembered.
    ///   - read: Reads a process's path, such as ``ProcessPath/live``.
    /// - Returns: The path, or `nil` if it isn't remembered and can't be read.
    func path(of pid: Int32, _ token: AuditToken?, reading read: (Int32, AuditToken?) -> String?) -> String? {
        if let path = path(of: token) { return path }
        let path = read(pid, token)
        remember(token, path: path)
        return path
    }
    
    /// Remember a process's executable.
    ///
    /// - Parameters:
    ///   - token: The process's audit token.
    ///   - path: Its executable's path. Nothing is remembered without both.
    func remember(_ token: AuditToken?, path: String?) {
        guard let token else { return }
        let image = Image(token)
        guard image != last else { return }
        remember(image, path: path)
    }
    
    /// Remember a process's executable.
    ///
    /// - Parameter process: The process.
    func remember(_ process: Process) {
        guard let token = process.audit_token else { return }
        let image = Image(token)
        /// Its executable is only read for the first event of a run.
        guard image != last else { return }
        remember(image, path: process.executable?.path)
    }
    
    /// Remember a process image's executable, unless the newer generation has it.
    ///
    /// An image's executable never changes, so the path already remembered stays: no paths are compared (a trace's
    /// are bridged strings, which compare slowly).
    ///
    /// - Parameters:
    ///   - image: The process image.
    ///   - path: Its executable's path. Nothing is remembered without one.
    private func remember(_ image: Image, path: String?) {
        guard let path else { return }
        last = image
        guard recent[image] == nil else { return }
        store(path, for: image)
    }
    
    /// Remember the process an exec or fork names that can go on to be a launched-by parent: an exec's new image, or a
    /// fork's forking process. Does nothing for any other event.
    ///
    /// An image exec replaces is never a parent again (its children's tokens name the new one), and a fork's child is
    /// named by its own fork or exec before it can be one.
    ///
    /// - Parameter message: The event.
    func remember(processesOf message: Message) {
        switch message.event {
        case .exec(let exec): remember(exec.target)
        case .fork: remember(message.process)
        default: break
        }
    }
    
    /// Keep a path the newer generation doesn't have, starting a new generation when it's full.
    ///
    /// - Parameters:
    ///   - path: The path.
    ///   - image: Its process image.
    private func store(_ path: String, for image: Image) {
        if recent.count >= capacity {
            older = recent
            recent = [:]
            last = nil
        }
        recent[image] = path
    }
}
