//
//  SystemProcessExecTableController.swift
//  ProjectSutro
//
//  NSTableView controller for process execution events (Ventura / macOS 13).
//  5 columns: Timestamp, Process name, Signing ID, Process path, Command line
//

import AppKit
import SutroESFramework
import SwiftUI
import Combine

class SystemProcessExecTableController: SystemEventsTableController {
    
    var allFilters: Binding<Filters>
    weak var systemExtensionManager: EndpointSecurityManager?
    weak var userPrefs: UserPrefs?
    var openEventJSON: ((UUID) -> Void)?
    
    var simple: Bool = false
    
    init(allFilters: Binding<Filters>, simple: Bool = false) {
        self.allFilters = allFilters
        self.simple = simple
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupColumns(for: .processExec(customizable: false))
        tableView.menu = NSMenu(title: "ProcessEventContextMenu")
        tableView.menu?.delegate = self
    }
    
    private func makeTextCellView() -> MonospacedTextCellView {
        MonospacedTextCellView()
    }

    override func openMetadataForRow(_ row: Int) {
        guard let id = messageForRow(row)?.id else { return }
        openEventJSON?(id)
    }
}

extension SystemProcessExecTableController {
    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        let minRowHeight: CGFloat = 22
        let maxRowHeight: CGFloat = 120

        guard let message = messageForRow(row),
              let commandLine = message.event.exec?.command_line,
              !commandLine.isEmpty,
              let commandLineColumn = tableView.tableColumn(withIdentifier: MessageTableColumnID.commandLine.identifier) else {
            return minRowHeight
        }

        let horizontalPadding: CGFloat = 8
        let availableWidth = max(40, commandLineColumn.width - horizontalPadding)
        let font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        let textHeight = (commandLine as NSString).boundingRect(
            with: NSSize(width: availableWidth, height: .greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading],
            attributes: [.font: font]
        ).height

        let desiredHeight = ceil(textHeight) + 8
        return min(maxRowHeight, max(minRowHeight, desiredHeight))
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let message = messageForRow(row),
              let tableColumn,
              let columnID = MessageTableColumnID(rawValue: tableColumn.identifier.rawValue) else {
            return nil
        }
        
        switch columnID {
        case .timestamp:
            let cell = makeTextCellView()
            cell.setText(formatTimestamp(message))
            return cell
            
        case .processName:
            let swiftUIView = ProcessExecEventNameView(message: message)
                .frame(maxWidth: .infinity, alignment: .leading)
            return SwiftUIHostingCellView(content: swiftUIView)
            
        case .signingID:
            let cell = makeTextCellView()
            cell.setText(message.event.exec?.target.signing_id ?? "")
            return cell
            
        case .processPath:
            let cell = SelectableTextCellView()
            cell.setText(message.event.exec?.target.executable?.path ?? "", lineBreakMode: .byTruncatingMiddle)
            return cell
            
        case .commandLine:
            let cell = MultilineTextCellView()
            cell.setText(message.event.exec?.command_line ?? "", maxLines: 8)
            return cell
            
        default:
            let cell = MonospacedTextCellView()
            cell.setText("")
            return cell
        }
    }
    
}

extension SystemProcessExecTableController {
    func tableView(_ tableView: NSTableView, menuForTableColumn column: NSTableColumn?, row: Int) -> NSMenu? {
        guard let message = messageForRow(row),
              let exec = message.event.exec else { return nil }
        
        return createContextMenu(for: message, exec: exec)
    }
    
    private func createContextMenu(for message: ESMessage, exec: ProcessExecEvent) -> NSMenu {
        let menu = NSMenu()
        
        let metadataItem = NSMenuItem(title: "Event metadata", action: #selector(openMetadata(_:)), keyEquivalent: "")
        metadataItem.representedObject = message.id
        menu.addItem(metadataItem)
        
        menu.addItem(NSMenuItem.separator())
        
        if let userPrefs = userPrefs, userPrefs.contextExecTargetPathFilter {
            if let exe = exec.target.executable, !exe.path.isEmpty {
                let filterItem = NSMenuItem(
                    title: "Filter target path: \"\(exe.path)\"",
                    action: #selector(filterTargetPath(_:)),
                    keyEquivalent: ""
                )
                filterItem.representedObject = exe.path
                menu.addItem(filterItem)
            }
        }
        
        let filterEventItem = NSMenuItem(
            title: "Filter event: \"\(message.es_event_type)\"",
            action: #selector(filterEvent(_:)),
            keyEquivalent: ""
        )
        filterEventItem.representedObject = message.es_event_type
        menu.addItem(filterEventItem)
        
        if let userPrefs = userPrefs, userPrefs.contextExecInitiatingEUIDFilter {
            if let euid = message.process.euid_human {
                let filterUserItem = NSMenuItem(
                    title: "Filter euid: \"\(euid)\"",
                    action: #selector(filterUser(_:)),
                    keyEquivalent: ""
                )
                filterUserItem.representedObject = euid
                menu.addItem(filterUserItem)
            }
        }
        
        if let userPrefs = userPrefs, userPrefs.contextExecInitiatingPathFilter {
            if let exe = message.process.executable, !exe.path.isEmpty {
                let filterItem = NSMenuItem(
                    title: "Filter initiating path: \"\(exe.path)\"",
                    action: #selector(filterInitiatingPath(_:)),
                    keyEquivalent: ""
                )
                filterItem.representedObject = exe.path
                menu.addItem(filterItem)
            }
        }
        
        menu.addItem(NSMenuItem.separator())
        
        let selectHeader = NSMenuItem(title: "Select", action: nil, keyEquivalent: "")
        selectHeader.isEnabled = false
        menu.addItem(selectHeader)
        
        if let tgtProcName = exec.target.executable?.name,
           let tgtProcPath = exec.target.executable?.path {
            let onlyItem = NSMenuItem(
                title: "→ Only: \"\(tgtProcName)\" events",
                action: #selector(selectOnlyProcess(_:)),
                keyEquivalent: ""
            )
            onlyItem.representedObject = ["path": tgtProcPath, "subtree": false]
            menu.addItem(onlyItem)
            
            let treeItem = NSMenuItem(
                title: "↕ Full tree: \"\(tgtProcName)\" events",
                action: #selector(selectProcessTree(_:)),
                keyEquivalent: ""
            )
            treeItem.representedObject = ["path": tgtProcPath, "subtree": true]
            menu.addItem(treeItem)
        }
        
        menu.addItem(NSMenuItem.separator())
        
        let advancedHeader = NSMenuItem(title: "Advanced", action: nil, keyEquivalent: "")
        advancedHeader.isEnabled = false
        menu.addItem(advancedHeader)
        
        if let userPrefs = userPrefs, userPrefs.contextExecTargetPathMute {
            if let procPath = exec.target.executable?.path {
                let procName = URL(fileURLWithPath: procPath).lastPathComponent
                let muteItem = NSMenuItem(
                    title: "Mute target path: \"\(procName)\"",
                    action: #selector(muteTargetPath(_:)),
                    keyEquivalent: ""
                )
                muteItem.representedObject = procPath
                menu.addItem(muteItem)
            }
        }
        
        if let userPrefs = userPrefs, userPrefs.contextExecInitiatingPathMute {
            if let path = message.process.executable?.path {
                let muteItem = NSMenuItem(
                    title: "Mute initiating path: \"\(message.process.executable?.name ?? path)\"",
                    action: #selector(muteInitiatingPath(_:)),
                    keyEquivalent: ""
                )
                muteItem.representedObject = path
                menu.addItem(muteItem)
            }
        }
        
        if let userPrefs = userPrefs, userPrefs.contextExecEventUnsubscribe {
            let unsubItem = NSMenuItem(
                title: "Unsubscribe: \"\(message.es_event_type)\"",
                action: #selector(unsubscribeEvent(_:)),
                keyEquivalent: ""
            )
            unsubItem.representedObject = message.es_event_type
            menu.addItem(unsubItem)
        }
        
        menu.delegate = self
        return menu
    }
    
    @objc private func openMetadata(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? UUID else { return }
        openEventJSON?(id)
    }
    
    @objc private func filterTargetPath(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        allFilters.wrappedValue.targetPaths.append(path)
    }
    
    @objc private func filterInitiatingPath(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        allFilters.wrappedValue.initiatingPaths.append(path)
    }
    
    @objc private func filterEvent(_ sender: NSMenuItem) {
        guard let eventType = sender.representedObject as? String else { return }
        allFilters.wrappedValue.events.append(eventType)
    }
    
    @objc private func filterUser(_ sender: NSMenuItem) {
        guard let euid = sender.representedObject as? String else { return }
        allFilters.wrappedValue.userIDs.append(euid)
    }
    
    @objc private func selectOnlyProcess(_ sender: NSMenuItem) {
        guard let dict = sender.representedObject as? [String: Any],
              let path = dict["path"] as? String else { return }
        allFilters.wrappedValue.rootIncludedTargetProcessPath = path
        allFilters.wrappedValue.shouldIncludeProcessSubTrees = false
    }
    
    @objc private func selectProcessTree(_ sender: NSMenuItem) {
        guard let dict = sender.representedObject as? [String: Any],
              let path = dict["path"] as? String else { return }
        allFilters.wrappedValue.rootIncludedTargetProcessPath = path
        allFilters.wrappedValue.shouldIncludeProcessSubTrees = true
    }
    
    @objc private func muteTargetPath(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String,
              let esm = systemExtensionManager else { return }
        esm.puntPathToMute(pathToMute: path, muteCase: ES_MUTE_PATH_TYPE_TARGET_LITERAL, pathEvents: [])
        esm.requestMutedPaths()
    }
    
    @objc private func muteInitiatingPath(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String,
              let esm = systemExtensionManager else { return }
        esm.puntPathToMute(pathToMute: path, muteCase: ES_MUTE_PATH_TYPE_LITERAL, pathEvents: [])
        esm.requestMutedPaths()
    }
    
    @objc private func unsubscribeEvent(_ sender: NSMenuItem) {
        guard let eventType = sender.representedObject as? String,
              let esm = systemExtensionManager else { return }
        esm.puntEventToUnsubscribe(eventString: eventType)
    }
}

extension SystemProcessExecTableController: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        let row = tableView.clickedRow
        guard row >= 0,
              let message = messageForRow(row),
              let exec = message.event.exec else { return }

        let contextMenu = createContextMenu(for: message, exec: exec)
        contextMenu.items.forEach { item in
            guard let copiedItem = item.copy() as? NSMenuItem else { return }
            copiedItem.target = self
            menu.addItem(copiedItem)
        }
    }
}
