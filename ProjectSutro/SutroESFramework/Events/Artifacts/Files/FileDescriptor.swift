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
    /// Derive the descriptor type's name.
    public mutating func enrich() {
        switch Int32(truncatingIfNeeded: fdtype) {
        case PROX_FDTYPE_PIPE:
            self.type = "PROX_FDTYPE_PIPE"
        case PROX_FDTYPE_SOCKET:
            self.type = "PROX_FDTYPE_SOCKET"
        case PROX_FDTYPE_PSEM:
            self.type = "PROX_FDTYPE_PSEM"
        case PROX_FDTYPE_PSHM:
            self.type = "PROX_FDTYPE_PSHM"
        case PROX_FDTYPE_ATALK:
            self.type = "PROX_FDTYPE_ATALK"
        case PROX_FDTYPE_NEXUS:
            self.type = "PROX_FDTYPE_NEXUS"
        case PROX_FDTYPE_VNODE:
            self.type = "PROX_FDTYPE_VNODE"
        case PROX_FDTYPE_KQUEUE:
            self.type = "PROX_FDTYPE_KQUEUE"
        case PROX_FDTYPE_CHANNEL:
            self.type = "PROX_FDTYPE_CHANNEL"
        case PROX_FDTYPE_FSEVENTS:
            self.type = "PROX_FDTYPE_FSEVENTS"
        case PROX_FDTYPE_NETPOLICY:
            self.type = "PROX_FDTYPE_NETPOLICY"
        default:
            self.type = "UNKNOWN"
        }
    }
}
