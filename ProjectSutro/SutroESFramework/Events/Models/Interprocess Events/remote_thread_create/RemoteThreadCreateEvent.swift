//
//  RemoteThreadCreateEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_remote_thread_create_t
public struct RemoteThreadCreateEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var target: Process
    public var thread_state: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: RemoteThreadCreateEvent, rhs: RemoteThreadCreateEvent) -> Bool {
        if lhs.target.audit_token_string != rhs.target.audit_token_string {
            return false
        }
        
        if lhs.thread_state != rhs.thread_state {
            return false
        }
        
        return true
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the thread create event
        let remoteThreadEvent: es_event_remote_thread_create_t = rawMessage.pointee.event.remote_thread_create
        let version = Int(rawMessage.pointee.version)
        
        self.target = Process(from: remoteThreadEvent.target.pointee, version: version)
        
        self.thread_state = remoteThreadEvent.thread_state.flatMap { Self.flavorName($0.pointee.flavor) }
    }
}


// MARK: - Thread state flavors
extension RemoteThreadCreateEvent {
    /// The name of a thread state's flavor on this Mac's architecture, as the Security Extension records `thread_state`.
    ///
    /// - Parameter flavor: The thread state's `thread_state_flavor_t`.
    /// - Returns: The flavor's name, or `nil` for one this architecture doesn't name.
    static func flavorName(_ flavor: thread_state_flavor_t) -> String? {
        #if arch(i386)
        return switch flavor {
        case x86_THREAD_STATE32: "x86_THREAD_STATE32"
        case x86_FLOAT_STATE32: "x86_FLOAT_STATE32"
        case x86_EXCEPTION_STATE32: "x86_EXCEPTION_STATE32"
        case x86_DEBUG_STATE32: "x86_DEBUG_STATE32"
        case x86_THREAD_STATE64: "x86_THREAD_STATE64"
        case x86_THREAD_FULL_STATE64: "x86_THREAD_FULL_STATE64"
        case x86_FLOAT_STATE64: "x86_FLOAT_STATE64"
        case x86_EXCEPTION_STATE64: "x86_EXCEPTION_STATE64"
        case x86_DEBUG_STATE64: "x86_DEBUG_STATE64"
        case x86_THREAD_STATE: "x86_THREAD_STATE"
        case x86_FLOAT_STATE: "x86_FLOAT_STATE"
        case x86_EXCEPTION_STATE: "x86_EXCEPTION_STATE"
        case x86_DEBUG_STATE: "x86_DEBUG_STATE"
        case x86_AVX_STATE32: "x86_AVX_STATE32"
        case x86_AVX_STATE64: "x86_THREAD_STATE32"
        case x86_AVX_STATE: "x86_AVX_STATE"
        case x86_AVX512_STATE32: "x86_AVX512_STATE32"
        case x86_AVX512_STATE64: "x86_AVX512_STATE64"
        case x86_AVX512_STATE: "x86_AVX512_STATE"
        case x86_PAGEIN_STATE: "x86_PAGEIN_STATE"
        case x86_INSTRUCTION_STATE: "x86_INSTRUCTION_STATE"
        case x86_LAST_BRANCH_STATE: "x86_LAST_BRANCH_STATE"
        case THREAD_STATE_NONE: "THREAD_STATE_NONE"
        default: nil
        }
        #elseif arch(arm64)
        return switch flavor {
        case ARM_THREAD_STATE: "ARM_THREAD_STATE"
        case ARM_VFP_STATE: "ARM_VFP_STATE"
        case ARM_EXCEPTION_STATE: "ARM_EXCEPTION_STATE"
        case ARM_DEBUG_STATE: "ARM_DEBUG_STATE"
        case THREAD_STATE_NONE: "THREAD_STATE_NONE"
        case ARM_THREAD_STATE32: "ARM_THREAD_STATE32"
        case ARM_THREAD_STATE64: "ARM_THREAD_STATE64"
        case ARM_EXCEPTION_STATE64: "ARM_EXCEPTION_STATE64"
        case ARM_NEON_STATE: "ARM_NEON_STATE"
        case ARM_NEON_STATE64: "ARM_NEON_STATE64"
        case ARM_DEBUG_STATE32: "ARM_DEBUG_STATE32"
        case ARM_DEBUG_STATE64: "ARM_DEBUG_STATE64"
        default: nil
        }
        #else
        return nil
        #endif
    }
}
