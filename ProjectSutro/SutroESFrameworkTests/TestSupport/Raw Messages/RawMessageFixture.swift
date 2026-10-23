//
//  RawMessageFixture.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity


// MARK: - Raw messages
/// An `es_message_t` built in memory, as Endpoint Security hands one to the Security Extension, for the capture code.
///
/// The fixture owns every allocation it makes (zeroed with `calloc`, strings copied with `strdup`) and frees them when
/// it's released. Swift can release an object right after its last use in the source, before the pointers into it
/// are done with, so make one with `XCTestCase.rawMessage(version:type:)`, which keeps it until the test ends. Its
/// initiating process is a platform binary, so a `Process` built from it never reads code signing certificates.
///
/// Never build a `ProcessExecEvent` from one: it retains the message with `es_retain_message`, which only takes a
/// message Endpoint Security delivered.
final class RawMessageFixture {
    /// The message.
    let message: UnsafeMutablePointer<es_message_t>
    /// Every allocation, freed with the fixture.
    private var allocations: [UnsafeMutableRawPointer] = []
    
    /// A message whose event is all zeros until a test fills it in.
    ///
    /// - Parameters:
    ///   - version: The message's version.
    ///   - type: The event's type.
    init(version: UInt32 = 10, type: es_event_type_t) {
        message = calloc(1, MemoryLayout<es_message_t>.stride)!.bindMemory(to: es_message_t.self, capacity: 1)
        allocations.append(UnsafeMutableRawPointer(message))
        message.pointee.version = version
        message.pointee.event_type = type
        message.pointee.action_type = ES_ACTION_TYPE_NOTIFY
        message.pointee.time = timespec(tv_sec: 1_791_072_114, tv_nsec: 394_127_173)
        message.pointee.process = process(path: "/usr/bin/true", signingID: "com.apple.true")
    }
    
    deinit {
        allocations.forEach { free($0) }
    }
    
    /// The message, as the capture code takes it.
    var raw: UnsafePointer<es_message_t> { UnsafePointer(message) }
    
    /// Zeroed values that live as long as the fixture.
    ///
    /// - Parameters:
    ///   - type: The values' type: a C struct, or another type whose zero bytes are a value.
    ///   - count: How many values, one after another.
    /// - Returns: A pointer to the first value.
    func allocate<T>(_ type: T.Type, count: Int = 1) -> UnsafeMutablePointer<T> {
        let memory = calloc(count, MemoryLayout<T>.stride)!
        allocations.append(memory)
        return memory.bindMemory(to: T.self, capacity: count)
    }
    
    /// A copy of a value that lives as long as the fixture.
    ///
    /// - Parameter value: A C struct, such as an event for the message's `event` union.
    /// - Returns: A pointer to the copy.
    func pointer<T>(_ value: T) -> UnsafeMutablePointer<T> {
        let pointer = allocate(T.self)
        pointer.pointee = value
        return pointer
    }
    
    /// A string token as Endpoint Security fills one: `length` bytes at `data`, followed by a NUL.
    ///
    /// - Parameter text: The text, or `nil` for a token whose `data` is `NULL` and whose `length` is 0.
    /// - Returns: The token.
    func token(_ text: String?) -> es_string_token_t {
        guard let text else { return es_string_token_t(length: 0, data: nil) }
        let copy = strdup(text)!
        allocations.append(UnsafeMutableRawPointer(copy))
        return es_string_token_t(length: text.utf8.count, data: copy)
    }
    
    /// A string token of raw bytes, which needn't end in a NUL or be UTF-8.
    ///
    /// - Parameters:
    ///   - bytes: The bytes at `data`.
    ///   - length: The token's `length`, or `nil` for the number of bytes.
    /// - Returns: The token.
    func token(bytes: [UInt8], length: Int? = nil) -> es_string_token_t {
        let memory = calloc(max(bytes.count, 1), 1)!
        allocations.append(memory)
        memory.copyMemory(from: bytes, byteCount: bytes.count)
        return es_string_token_t(length: length ?? bytes.count, data: memory.assumingMemoryBound(to: CChar.self))
    }
    
    /// A file with an all-zero `stat`.
    ///
    /// - Parameter path: The file's path.
    /// - Returns: The file.
    func file(_ path: String) -> UnsafeMutablePointer<es_file_t> {
        let file = allocate(es_file_t.self)
        file.pointee.path = token(path)
        return file
    }
    
    /// A process.
    ///
    /// - Parameters:
    ///   - path: The executable's path.
    ///   - signingID: The signing ID, or `nil` for a `NULL` token.
    ///   - teamID: The team ID, or `nil` for a `NULL` token.
    ///   - flags: The code signing flags.
    ///   - platform: Is it a platform binary? Only then does its code signing type need no certificates.
    ///   - pid: The process ID in its audit token.
    /// - Returns: The process.
    func process(path: String, signingID: String? = nil, teamID: String? = nil, flags: UInt32 = 0,
                 platform: Bool = true, pid: Int32 = 123) -> UnsafeMutablePointer<es_process_t> {
        let process = allocate(es_process_t.self)
        process.pointee.executable = file(path)
        process.pointee.signing_id = token(signingID)
        process.pointee.team_id = token(teamID)
        process.pointee.codesigning_flags = flags
        process.pointee.is_platform_binary = platform
        process.pointee.audit_token = Self.auditToken(pid: pid)
        process.pointee.parent_audit_token = Self.auditToken(pid: 1)
        process.pointee.responsible_audit_token = Self.auditToken(pid: pid)
        return process
    }
    
    /// An audit token for a root process.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - euid: The effective user ID.
    ///   - pidversion: The pid version.
    ///   - asid: The audit session ID.
    /// - Returns: The token, with audit user ID 4294967295 (none).
    static func auditToken(pid: Int32, euid: UInt32 = 0, pidversion: UInt32 = 1,
                           asid: UInt32 = 100_000) -> audit_token_t {
        audit_token_t(val: (UInt32.max, euid, 0, 0, 0, UInt32(bitPattern: pid), asid, pidversion))
    }
}


extension XCTestCase {
    /// A raw message that stays alive until the test ends.
    ///
    /// - Parameters:
    ///   - version: The message's version.
    ///   - type: The event's type.
    /// - Returns: The message's fixture.
    func rawMessage(version: UInt32 = 10, type: es_event_type_t) -> RawMessageFixture {
        let fixture = RawMessageFixture(version: version, type: type)
        addTeardownBlock { withExtendedLifetime(fixture) {} }
        return fixture
    }
}
