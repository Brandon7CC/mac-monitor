//
//  FileDescriptor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/31/25.
//

import Foundation

// Ensure FileDescriptor conforms to Codable and Equatable
public struct FileDescriptor: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var fdtype, fd: Int
    public var type: String
    public var pipe: FDPipe?
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case fdtype, fd, type, pipe
    }
    
    public init(from fd: es_fd_t) {
        self.fdtype = Int(fd.fdtype)
        self.fd = Int(fd.fd)
        
        switch Int32(fd.fdtype) {
        case PROX_FDTYPE_PIPE:
            self.type = "PROX_FDTYPE_PIPE"
            self.pipe = FDPipe(from: fd)
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
