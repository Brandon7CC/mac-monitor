//
//  MutedPath.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

import Foundation
import EndpointSecurity
import OSLog


public struct ESMutedPath: Identifiable, Codable, Hashable {
    public var id: String { "\(path)-\(type)" }
    public var type: String
    public var events: [String] = []
    public var path: String = ""
    public var eventCount: Int = 0
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine("\(path) \(type)")
    }
    
    public static func == (lhs: ESMutedPath, rhs: ESMutedPath) -> Bool {
        // TODO: This may cause a problem in the future. Add in the individual events.
        if lhs.path == rhs.path && lhs.type == rhs.type && lhs.eventCount == rhs.eventCount {
            return true
        }

        return false
    }
    
    init(fromRawESPath rawPath: es_muted_path_t) {
        // Set the path
        self.path = rawPath.path.string ?? ""
        
        self.type = getMuteCaseString(muteType: rawPath.type)
        
        // Get the number of events
        self.eventCount = rawPath.event_count
        
        // For each of those events...
        // Add the events the muting request was submitted for
        for index in 0..<eventCount {
            self.events.append(eventTypeToString(from: rawPath.events[index]))
        }
    }
    
    public init(type: String, events: [String], path: String) {
        self.type = type
        self.events = events
        self.path = path
        self.eventCount = events.count
    }
    
}

public struct ESMutedPaths: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var count: Int = 0
    public var paths: [ESMutedPath] = []
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(count)
    }
    
    public static func == (lhs: ESMutedPaths, rhs: ESMutedPaths) -> Bool {
        // TODO: This may cause a problem in the future add in each path.
        if lhs.id == rhs.id && lhs.count == rhs.count {
            return true
        }

        return false
    }
    
    init() {
        
    }
    
    init(fromRawESPaths rawPaths: UnsafeMutablePointer<es_muted_paths_t>) {
        self.count = rawPaths.pointee.count
        os_log("Parsing raw ES paths... there are \(rawPaths.pointee.count) of them")
        for index in 0..<self.count {
            self.paths.append(ESMutedPath(fromRawESPath: rawPaths.pointee.paths[index]))
        }
    }
}


/// A value as compact JSON with sorted keys.
///
/// - Parameter value: The value, such as an ``ESMutedPath``.
/// - Returns: The JSON, or "" if the value can't be encoded.
public func pathToJSON(value: Encodable) -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
    
    guard let encodedData = try? encoder.encode(value),
          let json = String(data: encodedData, encoding: .utf8) else { return "" }
    return json
}



public func decodePathJSON(pathJSON: String) -> ESMutedPath? {
    let json: Data = pathJSON.data(using: .utf8) ?? "".data(using: .utf8)!
    guard let esMutedPath: ESMutedPath = try? JSONDecoder().decode(ESMutedPath.self, from: json)
    else {
        os_log("Could not decode this path JSON!")
        return nil
    }
    return esMutedPath
}

public func encodePathJSON(path: ESMutedPath) -> String? {
    guard let data = try? JSONEncoder().encode(path) else { return nil }
    return String(data: data, encoding: .utf8)
}

