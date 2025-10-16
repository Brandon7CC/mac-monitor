//
//  FDPipe.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

// Ensure FDPipe conforms to Codable and Equatable
public struct FDPipe: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var pipe_id: Int64 = -1
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case pipe_id
    }
    
    public init(from fd: es_fd_t) {
        if fd.fdtype == PROX_FDTYPE_PIPE {
            pipe_id = Int64(fd.pipe.pipe_id)
        }
    }
}
