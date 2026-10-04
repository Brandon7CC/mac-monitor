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
    /// The new process image. The row may be shared with the events that process goes on to cause.
    @NSManaged public var target: ESProcess
    /// The `id` ``target`` had in this event (and exports). A shared row keeps the `id` of the first event that stored it.
    @NSManaged public var target_id: UUID?
    @NSManaged public var dyld_exec_path: String?
    @NSManaged public var script: ESFile?
    @NSManaged public var cwd: ESFile?
    @NSManaged public var last_fd: Int64
    @NSManaged public var fdsData: Data?
    @NSManaged public var image_cputype: Int64
    @NSManaged public var image_cpusubtype: Int64
    @NSManaged public var script_content: String?
    @NSManaged public var resolved_script_path: String?
}

extension ESProcessExecEvent : Identifiable {

}
