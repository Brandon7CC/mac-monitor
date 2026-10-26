//
//  FDPipe.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

public struct FDPipe: Codable, Equatable, Hashable {
    public var pipe_id: Int64 = -1
    
    public init(from fd: es_fd_t) {
        if fd.fdtype == PROX_FDTYPE_PIPE {
            /// A `uint64_t`, kept by bit pattern: one of 2^63 or more has no `Int64`.
            pipe_id = Int64(bitPattern: fd.pipe.pipe_id)
        }
    }
}
