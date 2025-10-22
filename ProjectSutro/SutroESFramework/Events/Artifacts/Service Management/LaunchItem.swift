//
//  LaunchItem.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/27/25.
//


/// Models a `es_btm_launch_item_t`:
/// https://developer.apple.com/documentation/endpointsecurity/es_btm_launch_item_t
public struct LaunchItem: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()

    // Type of launch item.
    public var item_type: Int16
    
    public var item_type_string: String
    public var item_url: String
    public var item_path: String // enrichment
    
    // Optional.  URL for app the item is attributed to.
    public var app_url: String?
    public var app_path: String? // enrichment
    
    // - True iff item is a legacy plist.
    // - True iff item is managed by MDM.
    public var legacy, managed: Bool
    
    // User ID for the item (may be user nobody (-2)).
    public var uid: Int64
    public var uid_human: String?
    
    // @note Mac Monitor enrichment
    public var plist_contents: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    init(from launchItem: es_btm_launch_item_t) {
        // MARK: - Legacy / Managed
        legacy = launchItem.legacy
        managed = launchItem.managed
        
        // MARK: - App
        if let appURLString = launchItem.app_url.toString(),
        let appURL = URL(string: appURLString) {
            app_url = appURLString
            app_path = appURL.path
        }
        
        // MARK: - Item
        item_url = launchItem.item_url.toString() ?? ""
        var itemPath: String
        if let itemURL = URL(string: item_url) {
            item_path = itemURL.path
            itemPath = itemURL.path
        } else {
            item_path = ""
            itemPath = ""
        }
        
        // MARK: Plist
        var plistPath: String?
        if legacy {
            plistPath = itemPath
        } else if let app_path = app_path {
            /// We need to resolve the relative plist path
            plistPath = URL(fileURLWithPath: app_path).appendingPathComponent(itemPath).path
        }
        
        item_type = Int16(launchItem.item_type.rawValue)
        switch launchItem.item_type {
        case ES_BTM_ITEM_TYPE_USER_ITEM:
            item_type_string = "ES_BTM_ITEM_TYPE_USER_ITEM"
        case ES_BTM_ITEM_TYPE_APP:
            item_type_string = "ES_BTM_ITEM_TYPE_APP"
        case ES_BTM_ITEM_TYPE_AGENT:
            item_type_string = "ES_BTM_ITEM_TYPE_AGENT"
            
            if let plistPath = plistPath {
                plist_contents = ProcessHelpers.getFileContents(at: plistPath)
            }
        case ES_BTM_ITEM_TYPE_DAEMON:
            item_type_string = "ES_BTM_ITEM_TYPE_DAEMON"
            
            if let plistPath = plistPath {
                plist_contents = ProcessHelpers.getFileContents(at: plistPath)
            }
        case ES_BTM_ITEM_TYPE_USER_ITEM:
            item_type_string = "ES_BTM_ITEM_TYPE_USER_ITEM"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM:
            item_type_string = "ES_BTM_ITEM_TYPE_LOGIN_ITEM"
        default:
            item_type_string = "UNKNOWN"
        }
    
        // MARK: - UID
        uid = Int64(launchItem.uid)
        if let rpw = getpwuid(launchItem.uid) {
            self.uid_human = String(cString: rpw.pointee.pw_name)
        }
    }
}
