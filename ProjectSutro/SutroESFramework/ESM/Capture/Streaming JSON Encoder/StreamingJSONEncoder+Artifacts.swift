//
//  StreamingJSONEncoder+Artifacts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Artifacts
extension StreamingJSONEncoder {
    /// Write the artifacts nearly every event carries (a file and its stat, times, audit tokens) member by member, as
    /// their synthesized `encode(to:)` writes them, without `Encoder` containers: 38 to 42% of an open or exec event's
    /// encode (open 17.4 to 10.1 µs, exec 30.7 to 18.8 µs, on an M1 Max). Their members are listed here, so a stored
    /// property added to one must be added here too (`StreamingJSONEncoderArtifactTests` fails until it is).
    ///
    /// - Parameter value: Any value.
    /// - Returns: Whether it was one of them, now written.
    @inline(never)
    func writeArtifact<T>(_ value: T) -> Bool {
        /// `value` as the artifact type it was just found to be, without a cast's cost.
        func rebound<Artifact>(_ write: (Artifact) -> Void) {
            withUnsafePointer(to: value) { $0.withMemoryRebound(to: Artifact.self, capacity: 1) { write($0.pointee) } }
        }
        if T.self == File.self {
            rebound(write(file:))
        } else if T.self == Stat.self {
            rebound(write(stat:))
        } else if T.self == TimeSpec.self {
            rebound(write(timeSpec:))
        } else if T.self == TimeVal.self {
            rebound(write(timeVal:))
        } else if T.self == AuditToken.self {
            rebound(write(auditToken:))
        } else {
            return false
        }
        return true
    }
    
    /// - Parameter file: A file, as `{"id":…,"path":…,"path_truncated":…,"stat":{…}}`.
    func write(file: File) {
        let frame = open(isObject: true)
        if member("id", in: frame) { write(uuid: file.id) }
        if member("path", in: frame) { write(string: file.path) }
        if member("path_truncated", in: frame) { write(bool: file.path_truncated) }
        if member("stat", in: frame) { write(stat: file.stat) }
    }
    
    /// - Parameter stat: A file's stat, its numbers then its four times.
    func write(stat: Stat) {
        let frame = open(isObject: true)
        func number(_ key: StaticString, _ value: Int64) { if member(key, in: frame) { write(integer: value) } }
        func time(_ key: StaticString, _ value: TimeSpec) { if member(key, in: frame) { write(timeSpec: value) } }
        if member("id", in: frame) { write(uuid: stat.id) }
        number("st_ino", stat.st_ino)
        number("st_dev", stat.st_dev)
        number("st_size", stat.st_size)
        number("st_blocks", stat.st_blocks)
        number("st_blksize", stat.st_blksize)
        number("st_flags", stat.st_flags)
        number("st_gen", stat.st_gen)
        number("st_mode", stat.st_mode)
        number("st_nlink", stat.st_nlink)
        number("st_uid", stat.st_uid)
        number("st_gid", stat.st_gid)
        number("st_rdev", stat.st_rdev)
        time("st_atimespec", stat.st_atimespec)
        time("st_mtimespec", stat.st_mtimespec)
        time("st_ctimespec", stat.st_ctimespec)
        time("st_birthtimespec", stat.st_birthtimespec)
    }
    
    /// - Parameter timeSpec: Seconds and nanoseconds.
    func write(timeSpec: TimeSpec) {
        let frame = open(isObject: true)
        if member("id", in: frame) { write(uuid: timeSpec.id) }
        if member("tv_sec", in: frame) { write(integer: timeSpec.tv_sec) }
        if member("tv_nsec", in: frame) { write(integer: timeSpec.tv_nsec) }
    }
    
    /// - Parameter timeVal: Seconds and microseconds.
    func write(timeVal: TimeVal) {
        let frame = open(isObject: true)
        if member("id", in: frame) { write(uuid: timeVal.id) }
        if member("tv_sec", in: frame) { write(integer: timeVal.tv_sec) }
        if member("tv_usec", in: frame) { write(integer: timeVal.tv_usec) }
    }
    
    /// - Parameter auditToken: An audit token's fields.
    func write(auditToken token: AuditToken) {
        let frame = open(isObject: true)
        func number(_ key: StaticString, _ value: some BinaryInteger) {
            if member(key, in: frame) { write(integer: value) }
        }
        if member("id", in: frame) { write(uuid: token.id) }
        number("pid", token.pid)
        number("pidversion", token.pidversion)
        number("asid", token.asid)
        number("auid", token.auid)
        number("euid", token.euid)
        number("ruid", token.ruid)
        number("rgid", token.rgid)
        number("egid", token.egid)
    }
    
    /// Start an object's member whose key is plain ASCII, which needs no escaping: the key, quoted, and a colon,
    /// copied as they are.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - frame: The object's frame.
    /// - Returns: `false`, writing nothing, if the object was already closed.
    func member(_ key: StaticString, in frame: FrameReference) -> Bool {
        guard element(in: frame) else { return false }
        if state.pointee.sortsKeys {
            state.pointee.members.append(Member(key: key.description, start: state.pointee.count))
        }
        let length = key.utf8CodeUnitCount
        reserve(length + 3)
        let out = state.pointee.base + state.pointee.count
        out[0] = UInt8(ascii: "\"")
        (out + 1).update(from: key.utf8Start, count: length)
        out[length + 1] = UInt8(ascii: "\"")
        out[length + 2] = UInt8(ascii: ":")
        state.pointee.count += length + 3
        return true
    }
}
