//
//  CustomizableUnifiedSystemEventsTableController.swift
//  ProjectSutro
//
//  NSTableView controller for unified system events (Sonoma+ / macOS 14).
//  9 columns: Timestamp, Event type, Context, Effective user, Source process,
//             Initiating pid (hidden), ppid (hidden), Source process path (hidden), Source Signing ID
//

import AppKit
import SutroESFramework
import SwiftUI
import Combine

@available(macOS 14.0, *)
class CustomizableUnifiedSystemEventsTableController: SystemEventsTableController {
    
    var allFilters: Binding<Filters>
    weak var systemExtensionManager: EndpointSecurityManager?
    weak var userPrefs: UserPrefs?
    var openEventJSON: ((UUID) -> Void)?
    
    private var columnVisibility: [MessageTableColumnID: Bool] = [
        .timestamp: true,
        .eventType: true,
        .context: true,
        .effectiveUser: true,
        .sourceProcess: true,
        .initiatingPID: false,
        .ppid: false,
        .sourceProcessPath: false,
        .sourceSigningID: true
    ]
    
    init(allFilters: Binding<Filters>) {
        self.allFilters = allFilters
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupColumns(for: .unified(customizable: true))
        applyColumnVisibility()
        tableView.menu = NSMenu(title: "UnifiedEventContextMenu")
        tableView.menu?.delegate = self
    }
    
    private func applyColumnVisibility() {
        tableView.tableColumns.forEach { column in
            guard let columnID = MessageTableColumnID(rawValue: column.identifier.rawValue) else { return }
            column.isHidden = !(columnVisibility[columnID] ?? true)
        }
    }
    
    func setColumnVisibility(_ columnID: MessageTableColumnID, visible: Bool) {
        columnVisibility[columnID] = visible
        if let column = tableView.tableColumn(withIdentifier: columnID.identifier) {
            column.isHidden = !visible
        }
    }
    
    private func makeTextCellView() -> MonospacedTextCellView {
        MonospacedTextCellView()
    }

    override func openMetadataForRow(_ row: Int) {
        guard let id = messageForRow(row)?.id else { return }
        openEventJSON?(id)
    }
}

@available(macOS 14.0, *)
extension CustomizableUnifiedSystemEventsTableController {
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
            
        case .eventType:
            let swiftUIView = SystemEventTypeLabel(message: message)
                .frame(maxWidth: .infinity, alignment: .leading)
                .truncationMode(.middle)
            return SwiftUIHostingCellView(content: swiftUIView)
            
        case .context:
            let cell = makeTextCellView()
            cell.setText(message.context ?? "", lineBreakMode: .byTruncatingMiddle)
            return cell
            
        case .effectiveUser:
            let cell = makeTextCellView()
            cell.setText(message.process.euid_human ?? "")
            return cell
            
        case .sourceProcess:
            let cell = makeTextCellView()
            cell.setText(message.process.executable?.name ?? "")
            return cell
            
        case .initiatingPID:
            let cell = makeTextCellView()
            cell.setText(String(message.process.pid))
            return cell
            
        case .ppid:
            let cell = makeTextCellView()
            cell.setText(String(message.process.ppid))
            return cell
            
        case .sourceProcessPath:
            let cell = makeTextCellView()
            cell.setText(message.process.executable?.path ?? "", lineBreakMode: .byTruncatingMiddle)
            return cell
            
        case .sourceSigningID:
            let cell = makeTextCellView()
            cell.setText(message.process.signing_id ?? "")
            return cell
            
        default:
            let cell = MonospacedTextCellView()
            cell.setText("")
            return cell
        }
    }
}

@available(macOS 14.0, *)
extension CustomizableUnifiedSystemEventsTableController {
    func tableView(_ tableView: NSTableView, menuForTableColumn column: NSTableColumn?, row: Int) -> NSMenu? {
        guard let message = messageForRow(row) else { return nil }
        
        return createContextMenu(for: message)
    }
    
    private func createContextMenu(for message: ESMessage) -> NSMenu {
        let menu = NSMenu()
        
        let metadataItem = NSMenuItem(title: "Event metadata", action: #selector(openMetadata(_:)), keyEquivalent: "")
        metadataItem.representedObject = message.id
        menu.addItem(metadataItem)
        
        menu.addItem(NSMenuItem.separator())
        
        if let userPrefs = userPrefs, userPrefs.contextInitiatingPathFilter {
            if let path = message.process.executable?.path, !path.isEmpty {
                let filterItem = NSMenuItem(
                    title: "Filter initiating path: \"\(message.process.executable?.name ?? path)\"",
                    action: #selector(filterInitiatingPath(_:)),
                    keyEquivalent: ""
                )
                filterItem.representedObject = path
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

        if let userPrefs = userPrefs, userPrefs.contextInitiatingEUIDFilter {
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
        
        menu.addItem(NSMenuItem.separator())
        
        let selectHeader = NSMenuItem(title: "Select", action: nil, keyEquivalent: "")
        selectHeader.isEnabled = false
        menu.addItem(selectHeader)
        
        if let procName = message.process.executable?.name,
           let procPath = message.process.executable?.path {
            let onlyItem = NSMenuItem(
                title: "→ Only: \"\(procName)\" events",
                action: #selector(selectOnlyProcess(_:)),
                keyEquivalent: ""
            )
            onlyItem.representedObject = ["path": procPath, "subtree": false]
            menu.addItem(onlyItem)

            let treeItem = NSMenuItem(
                title: "↕ Full tree: \"\(procName)\" events",
                action: #selector(selectProcessTree(_:)),
                keyEquivalent: ""
            )
            treeItem.representedObject = ["path": procPath, "subtree": true]
            menu.addItem(treeItem)
        }
        
        menu.addItem(NSMenuItem.separator())
        
        let advancedHeader = NSMenuItem(title: "Advanced", action: nil, keyEquivalent: "")
        advancedHeader.isEnabled = false
        menu.addItem(advancedHeader)
        
        if let userPrefs = userPrefs, userPrefs.contextTargetPathFilter,
           let targetPath = message.target_path, !targetPath.isEmpty {
            let displayPath: String
            if IntelligentEventTargeting.targetShouldBeParentDir(esEventType: message.es_event_type) {
                displayPath = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
            } else {
                displayPath = targetPath
            }
            let filterTargetItem = NSMenuItem(
                title: "Filter target path: \"\(displayPath)/\"",
                action: #selector(filterTargetPath(_:)),
                keyEquivalent: ""
            )
            filterTargetItem.representedObject = displayPath
            menu.addItem(filterTargetItem)
        }

        if let userPrefs = userPrefs, userPrefs.contextInitiatingPathMute {
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

        if let userPrefs = userPrefs, userPrefs.contextTargetPathMute,
           let targetPath = message.target_path, !targetPath.isEmpty {
            let muteCase: es_mute_path_type_t
            let displayPath: String
            if IntelligentEventTargeting.targetShouldBeParentDir(esEventType: message.es_event_type) {
                displayPath = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
                muteCase = ES_MUTE_PATH_TYPE_TARGET_PREFIX
            } else {
                displayPath = targetPath
                muteCase = ES_MUTE_PATH_TYPE_TARGET_LITERAL
            }
            let muteTargetItem = NSMenuItem(
                title: "Mute target path event: \"\(displayPath)/\"",
                action: #selector(muteTargetPath(_:)),
                keyEquivalent: ""
            )
            muteTargetItem.representedObject = ["path": displayPath, "muteCase": muteCase.rawValue, "eventType": message.es_event_type]
            menu.addItem(muteTargetItem)
        }

        if let userPrefs = userPrefs, userPrefs.contextEventUnsubscribe {
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
        allFilters.wrappedValue.rootIncludedInitiatingProcessPath = path
        allFilters.wrappedValue.shouldIncludeProcessSubTrees = false
    }

    @objc private func selectProcessTree(_ sender: NSMenuItem) {
        guard let dict = sender.representedObject as? [String: Any],
              let path = dict["path"] as? String else { return }
        allFilters.wrappedValue.rootIncludedInitiatingProcessPath = path
        allFilters.wrappedValue.shouldIncludeProcessSubTrees = true
    }

    @objc private func muteTargetPath(_ sender: NSMenuItem) {
        guard let dict = sender.representedObject as? [String: Any],
              let path = dict["path"] as? String,
              let muteCaseRaw = dict["muteCase"] as? UInt32,
              let eventType = dict["eventType"] as? String,
              let esm = systemExtensionManager else { return }
        let muteCase = es_mute_path_type_t(muteCaseRaw)
        esm.puntPathToMute(pathToMute: path, muteCase: muteCase, pathEvents: [eventType])
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

@available(macOS 14.0, *)
extension CustomizableUnifiedSystemEventsTableController: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        let row = tableView.clickedRow
        guard row >= 0,
              let message = messageForRow(row) else { return }

        let contextMenu = createContextMenu(for: message)
        contextMenu.items.forEach { item in
            guard let copiedItem = item.copy() as? NSMenuItem else { return }
            copiedItem.target = self
            menu.addItem(copiedItem)
        }
    }
}
