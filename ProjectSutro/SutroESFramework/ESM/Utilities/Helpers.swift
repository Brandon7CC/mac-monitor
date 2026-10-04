//
//  Helpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import AppKit
import SystemConfiguration
import OSLog
import UniformTypeIdentifiers


// MARK: - File System helpers
// @discussion used for getting the console user's hoem directory
extension FileManager {
    var consoleUserHome: URL? {
        var homeDirectory: URL?
        if let consoleUser = SCDynamicStoreCopyConsoleUser(nil, nil, nil) as String?, consoleUser != "loginwindow" {
            homeDirectory = URL(fileURLWithPath: "/Users/\(consoleUser)")
        }
        return homeDirectory
    }
}

// @note show something in `Finder.app`
public func showInFinder(filePath: String) {
    let url = URL(fileURLWithPath: filePath)
    NSWorkspace.shared.activateFileViewerSelecting([url])
}


extension URL {
    var isDirectory: Bool {
        (try? resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
    }
    var isQuarantined: Bool {
        ((try? resourceValues(forKeys: [.quarantinePropertiesKey])) != nil)
    }
}
// MARK: - End file system helpers

// MARK: - AppKit UI components
public func showMuteSavePanel() -> URL? {
    let savePanel = NSSavePanel()
    savePanel.allowedContentTypes = [UTType.json]
    savePanel.canCreateDirectories = true
    savePanel.isExtensionHidden = false
    savePanel.allowsOtherFileTypes = false
    savePanel.title = "Save path mute set"
    savePanel.message = "Choose a directory to export the mute set to"
    savePanel.nameFieldLabel = "Mute set file name:"
    let response = savePanel.runModal()
    return response == .OK ? savePanel.url : nil
}

func promptFullDiskAccess() -> Bool {
    let alert = NSAlert()
    alert.messageText = "Enable Full Disk Access"
    alert.informativeText = "Monitoring System Events requires Full Disk Access"
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Open System Settings")
    return alert.runModal() == .alertFirstButtonReturn
}
