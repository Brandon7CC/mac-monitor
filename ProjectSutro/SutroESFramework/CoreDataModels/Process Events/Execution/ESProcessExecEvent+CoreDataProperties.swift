//
//  RCESProcessExecEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData


extension ESProcessExecEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESProcessExecEvent> {
        return NSFetchRequest<ESProcessExecEvent>(entityName: "ESProcessExecEvent")
    }
    
    @NSManaged public var argsData: Data?
    @NSManaged public var envData: Data?
    @NSManaged public var command_line: String?
    @NSManaged public var id: UUID?
    @NSManaged public var certificateChainData: Data?
    @NSManaged public var target: ESProcess
    @NSManaged public var dyld_exec_path: String?
    @NSManaged public var script: ESFile?
    @NSManaged public var cwd: ESFile?
    @NSManaged public var last_fd: Int64
    @NSManaged public var fdsData: Data?
    @NSManaged public var image_cputype: Int64
    @NSManaged public var image_cpusubtype: Int64
    @NSManaged public var script_content: String?
}

extension ESProcessExecEvent : Identifiable {

}
