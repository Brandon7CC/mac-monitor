//
//  FileDescriptor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/31/25.
//

import Foundation

public struct FileDescriptor: Codable, Hashable {
    public var fdtype, fd: Int
    public var type = ""
    public var pipe: FDPipe?
    
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


// MARK: - Labels
extension FileDescriptor {
    /// An exec's descriptors as Event Facts lists them, each labeled by its number and type, a pipe's ID, and the
    /// earlier descriptor of the same pipe: `0 PIPE 7, 1 PIPE 8, 10 PIPE 8 (same pipe as 1)`.
    ///
    /// - Parameter fds: The descriptors, in order.
    /// - Returns: Their labels, joined by ", ".
    public static func list(_ fds: [FileDescriptor]) -> String {
        labels(fds).joined(separator: ", ")
    }

    /// Each descriptor's label: its number, its type without `PROX_FDTYPE_`, and a pipe's ID. A pipe an earlier
    /// descriptor in the list has too adds that descriptor's number.
    ///
    /// - Parameter fds: The descriptors, in order.
    /// - Returns: The labels, in order.
    static func labels(_ fds: [FileDescriptor]) -> [String] {
        var firstOfPipe: [Int64: Int] = [:]
        return fds.map { descriptor in
            let label = "\(descriptor.fd) \(descriptor.type.droppingPrefix("PROX_FDTYPE_"))"
            guard let pipe = descriptor.pipe?.pipe_id else { return label }
            /// The ID is a `uint64_t`, kept by bit pattern.
            let pipeLabel = "\(label) \(UInt64(bitPattern: pipe))"
            guard let first = firstOfPipe[pipe] else {
                firstOfPipe[pipe] = descriptor.fd
                return pipeLabel
            }
            return "\(pipeLabel) (same pipe as \(first))"
        }
    }
}
