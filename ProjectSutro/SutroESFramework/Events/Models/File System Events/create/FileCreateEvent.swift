//
//  FileCreateEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_create_t
public struct FileCreateEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var destination_type: Int
    public var destination_type_string = ""
    
    public var destination: FileDestination
    
    /// Only if message >= 2
    public var acl: String?
    
    public var is_quarantined: Int16 = 0
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FileCreateEvent, rhs: FileCreateEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>, shouldCheckQuarantine: Bool = false) {
        let messageVersion: Int = Int(rawMessage.pointee.version)
        let create: es_event_create_t = rawMessage.pointee.event.create
        /*
         The type of destination for the event, which can be either an existing file
         or information that describes a new file’s pending location.
         */
        self.destination_type = Int(create.destination_type.rawValue)
        self.destination = FileDestination.from(create: create)
        enrich()
        switch(create.destination_type) {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            self.is_quarantined = Int16(ProcessHelpers.isFileQuarantined(filePath: destination.existing_file!.path))
        case ES_DESTINATION_TYPE_NEW_PATH:
            if let new_path = destination.new_path {
                let dir: String = new_path.dir.path
                let path: String = "\(dir)\\/\(new_path.filename)"
                self.is_quarantined = Int16(ProcessHelpers.isFileQuarantined(filePath: path))
            }
        default:
            break
        }
        
        if messageVersion >= 2 {
            if let aclObj = create.acl {
                self.acl = aclObj.toString()
            }
        }
    }
}


// MARK: - Mac Monitor enrichment
extension FileCreateEvent: ESEnrichable {
    /// Derive the destination type's name.
    ///
    /// Not derived: `is_quarantined`, which is read from the file.
    public mutating func enrich() {
        destination_type_string = FileDestination.typeName(destination_type)
    }
}

extension acl_t {
    func toString() -> String? {
        let size = acl_size(self)
        let extBuffer = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<Int8>.alignment)
        defer { extBuffer.deallocate() }

        guard acl_copy_ext(extBuffer, self, size) != -1 else {
            perror("acl_copy_ext")
            return nil
        }

        guard let intACL = acl_copy_int(extBuffer) else {
            perror("acl_copy_int")
            return nil
        }
        defer { acl_free(UnsafeMutableRawPointer(intACL)) }

        var len: Int = 0
        guard let text = acl_to_text(intACL, &len) else {
            perror("acl_to_text")
            return nil
        }
        defer { acl_free(UnsafeMutableRawPointer(text)) }

        return String(cString: text)
    }
}
