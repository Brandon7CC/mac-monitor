//
//  MessageTableColumn.swift
//  ProjectSutro
//
//  NSTableColumn identifiers and definitions for Message tables.
//

import AppKit
import SutroESFramework

enum MessageTableColumnID: String, CaseIterable {
    case timestamp = "Timestamp"
    case eventType = "Event type"
    case context = "Context"
    case effectiveUser = "Effective user"
    case sourceProcess = "Source process"
    case initiatingPID = "Initiating pid"
    case ppid = "ppid"
    case sourceProcessPath = "Source process path"
    case sourceSigningID = "Source Signing ID"
    
    case processName = "Process name"
    case signingID = "Signing ID"
    case processPath = "Process path"
    case commandLine = "Command line"
    
    var identifier: NSUserInterfaceItemIdentifier {
        NSUserInterfaceItemIdentifier(rawValue: self.rawValue)
    }
}

enum MessageTableColumnFactory {
    static func createUnifiedColumns(isCustomizable: Bool) -> [NSTableColumn] {
        var columns: [NSTableColumn] = []
        
        let timestamp = NSTableColumn(identifier: MessageTableColumnID.timestamp.identifier)
        timestamp.title = "Timestamp"
        timestamp.minWidth = 100
        timestamp.maxWidth = 100
        timestamp.width = 100
        timestamp.resizingMask = .userResizingMask
        columns.append(timestamp)
        
        let eventType = NSTableColumn(identifier: MessageTableColumnID.eventType.identifier)
        eventType.title = "Event type"
        eventType.minWidth = 150
        eventType.maxWidth = 400
        eventType.width = 200
        eventType.resizingMask = .userResizingMask
        columns.append(eventType)
        
        let context = NSTableColumn(identifier: MessageTableColumnID.context.identifier)
        context.title = "Context"
        context.minWidth = 100
        context.maxWidth = 2000
        context.width = 150
        context.resizingMask = .autoresizingMask
        columns.append(context)
        
        let effectiveUser = NSTableColumn(identifier: MessageTableColumnID.effectiveUser.identifier)
        effectiveUser.title = "Effective user"
        effectiveUser.minWidth = 80
        effectiveUser.maxWidth = 120
        effectiveUser.width = 90
        effectiveUser.resizingMask = .userResizingMask
        columns.append(effectiveUser)
        
        let sourceProcess = NSTableColumn(identifier: MessageTableColumnID.sourceProcess.identifier)
        sourceProcess.title = "Source process"
        sourceProcess.minWidth = 80
        sourceProcess.maxWidth = 200
        sourceProcess.width = 100
        sourceProcess.resizingMask = .userResizingMask
        columns.append(sourceProcess)
        
        if isCustomizable {
            let initiatingPID = NSTableColumn(identifier: MessageTableColumnID.initiatingPID.identifier)
            initiatingPID.title = "Initiating pid"
            initiatingPID.minWidth = 30
            initiatingPID.maxWidth = 80
            initiatingPID.width = 50
            initiatingPID.resizingMask = .userResizingMask
            initiatingPID.isHidden = true
            columns.append(initiatingPID)
            
            let ppid = NSTableColumn(identifier: MessageTableColumnID.ppid.identifier)
            ppid.title = "ppid"
            ppid.minWidth = 20
            ppid.maxWidth = 50
            ppid.width = 30
            ppid.resizingMask = .userResizingMask
            ppid.isHidden = true
            columns.append(ppid)
            
            let sourceProcessPath = NSTableColumn(identifier: MessageTableColumnID.sourceProcessPath.identifier)
            sourceProcessPath.title = "Source process path"
            sourceProcessPath.minWidth = 50
            sourceProcessPath.maxWidth = 500
            sourceProcessPath.width = 200
            sourceProcessPath.resizingMask = .autoresizingMask
            sourceProcessPath.isHidden = true
            columns.append(sourceProcessPath)
        }
        
        let sourceSigningID = NSTableColumn(identifier: MessageTableColumnID.sourceSigningID.identifier)
        sourceSigningID.title = "Source Signing ID"
        sourceSigningID.minWidth = 80
        sourceSigningID.maxWidth = 200
        sourceSigningID.width = 100
        sourceSigningID.resizingMask = .autoresizingMask
        columns.append(sourceSigningID)
        
        return columns
    }
    
    static func createProcessExecColumns(isCustomizable: Bool) -> [NSTableColumn] {
        var columns: [NSTableColumn] = []
        
        let timestamp = NSTableColumn(identifier: MessageTableColumnID.timestamp.identifier)
        timestamp.title = "Timestamp"
        timestamp.minWidth = 100
        timestamp.maxWidth = 100
        timestamp.width = 100
        timestamp.resizingMask = .userResizingMask
        if isCustomizable {
            timestamp.isHidden = true
        }
        columns.append(timestamp)
        
        let processName = NSTableColumn(identifier: MessageTableColumnID.processName.identifier)
        processName.title = "Process name"
        processName.minWidth = 120
        processName.maxWidth = 500
        processName.width = 200
        processName.resizingMask = .userResizingMask
        columns.append(processName)
        
        let signingID = NSTableColumn(identifier: MessageTableColumnID.signingID.identifier)
        signingID.title = "Signing ID"
        signingID.minWidth = 120
        signingID.maxWidth = 500
        signingID.width = 240
        signingID.resizingMask = .userResizingMask
        columns.append(signingID)
        
        let processPath = NSTableColumn(identifier: MessageTableColumnID.processPath.identifier)
        processPath.title = "Process path"
        processPath.minWidth = 120
        processPath.maxWidth = 600
        processPath.width = 260
        processPath.resizingMask = .userResizingMask
        columns.append(processPath)
        
        let commandLine = NSTableColumn(identifier: MessageTableColumnID.commandLine.identifier)
        commandLine.title = "Command line"
        commandLine.minWidth = 400
        commandLine.maxWidth = CGFloat.greatestFiniteMagnitude
        commandLine.width = 1200
        commandLine.resizingMask = .autoresizingMask
        columns.append(commandLine)
        
        return columns
    }
}
