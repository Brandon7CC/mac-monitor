//
//  Helpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import AppKit
import OSLog
import UniformTypeIdentifiers


// MARK: - AppKit UI components
/// Ask where to export a mute set.
///
/// - Parameters:
///   - title: The panel's title.
///   - name: The file name to suggest.
/// - Returns: The file to write, or `nil` if the user cancelled.
public func showMuteSavePanel(title: String = "Save path mute set", name: String = "") -> URL? {
    let savePanel = NSSavePanel()
    savePanel.allowedContentTypes = [UTType.json]
    savePanel.canCreateDirectories = true
    savePanel.isExtensionHidden = false
    savePanel.allowsOtherFileTypes = false
    savePanel.title = title
    savePanel.message = "Choose a directory to export the mute set to"
    savePanel.nameFieldLabel = "Mute set file name:"
    savePanel.nameFieldStringValue = name
    let response = savePanel.runModal()
    return response == .OK ? savePanel.url : nil
}

/// Ask for a mute file to import: a Mac Monitor mute file, or a list exported before 3.0.
///
/// - Returns: The file to read, or `nil` if the user cancelled.
public func showMuteOpenPanel() -> URL? {
    let openPanel = NSOpenPanel()
    openPanel.allowedContentTypes = [UTType.json, UTType.plainText]
    openPanel.allowsOtherFileTypes = true
    openPanel.canChooseDirectories = false
    openPanel.allowsMultipleSelection = false
    openPanel.title = "Import path mute set"
    openPanel.message = "Choose a mute file to replace or add to the saved mute set"
    let response = openPanel.runModal()
    return response == .OK ? openPanel.url : nil
}
