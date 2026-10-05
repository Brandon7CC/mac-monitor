//
//  MProtectEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/14/25.
//

import Foundation


/// @note see `man mprotect`
private func decodeProtectionFlags(_ protection: Int32) -> [String] {
    /// No permissions at all.
    guard protection != VM_PROT_NONE else { return ["VM_PROT_NONE"] }
    
    var flags: [String] = []
    /// The pages can be read.
    if protection & VM_PROT_READ != 0 { flags.append("VM_PROT_READ") }
    /// The pages can be written.
    if protection & VM_PROT_WRITE != 0 { flags.append("VM_PROT_WRITE") }
    /// The pages can be executed.
    if protection & VM_PROT_EXECUTE != 0 { flags.append("VM_PROT_EXECUTE") }
    
    return flags
}

/// @brief Control protection of pages
/// A type for an event that indicates a change to protection of memory-mapped pages.
/// https://developer.apple.com/documentation/endpointsecurity/es_event_mprotect_t
public struct MProtectEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var protection: Int32
    public var address, size: Int64
    
    /// @note Mac Monitor enrichment
    public var hex_address = ""
    public var kb_size: Int64 = 0
    public var flags: [String] = []
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: MProtectEvent, rhs: MProtectEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_mprotect_t = rawMessage.pointee.event.mprotect
        
        self.protection = event.protection
        /// `user_addr_t` and `user_size_t` are unsigned, kept by bit pattern: one of 2^63 or more has no `Int64`.
        self.address = Int64(bitPattern: event.address)
        self.size = Int64(bitPattern: event.size)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension MProtectEvent: ESEnrichable {
    /// Derive the address in hex, the size in KB, and the protection's flags.
    public mutating func enrich() {
        self.hex_address = ProcessHelpers.toHex(UInt64(bitPattern: address))
        self.kb_size = Int64(ProcessHelpers
            .sizeFromHexNormalized(size: Double(UInt64(bitPattern: size))))
        self.flags = decodeProtectionFlags(protection)
    }
}
