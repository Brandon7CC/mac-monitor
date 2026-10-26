//
//  FileDescriptor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/31/25.
//

import Foundation

// Ensure FileDescriptor conforms to Codable and Equatable
public struct FileDescriptor: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var fdtype, fd: Int
    public var type = ""
    public var pipe: FDPipe?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case fdtype, fd, type, pipe
    }
    
    public init(from fd: es_fd_t) {
        self.fdtype = Int(fd.fdtype)
        self.fd = Int(fd.fd)
        
        if Int32(fd.fdtype) == PROX_FDTYPE_PIPE {
            self.pipe = FDPipe(from: fd)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension FileDescriptor: ESEnrichable {
    /// `PROX_FDTYPE_*`: what the descriptor refers to.
    private static let typeNames = ConstantNames([
        PROX_FDTYPE_PIPE: "PROX_FDTYPE_PIPE",
        PROX_FDTYPE_SOCKET: "PROX_FDTYPE_SOCKET",
        PROX_FDTYPE_PSEM: "PROX_FDTYPE_PSEM",
        PROX_FDTYPE_PSHM: "PROX_FDTYPE_PSHM",
        PROX_FDTYPE_ATALK: "PROX_FDTYPE_ATALK",
        PROX_FDTYPE_NEXUS: "PROX_FDTYPE_NEXUS",
        PROX_FDTYPE_VNODE: "PROX_FDTYPE_VNODE",
        PROX_FDTYPE_KQUEUE: "PROX_FDTYPE_KQUEUE",
        PROX_FDTYPE_CHANNEL: "PROX_FDTYPE_CHANNEL",
        PROX_FDTYPE_FSEVENTS: "PROX_FDTYPE_FSEVENTS",
        PROX_FDTYPE_NETPOLICY: "PROX_FDTYPE_NETPOLICY",
    ])
    
    /// Derive the descriptor type's name.
    public mutating func enrich() {
        type = Self.typeNames.name(of: Int(Int32(truncatingIfNeeded: fdtype)))
    }
}
