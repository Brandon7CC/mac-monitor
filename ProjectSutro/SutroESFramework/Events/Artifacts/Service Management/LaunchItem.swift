//
//  LaunchItem.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/27/25.
//


/// Models a `es_btm_launch_item_t`:
/// https://developer.apple.com/documentation/endpointsecurity/es_btm_launch_item_t
public struct LaunchItem: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()

    // Type of launch item.
    public var item_type: Int16
    
    public var item_type_string = ""
    public var item_url: String
    public var item_path = "" // enrichment
    
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
        /// Optional: `nil` (eslogger's `null`) when the item has no app. Kept as written, even when it isn't a URL.
        app_url = launchItem.app_url.string
        
        // MARK: - Item
        item_url = launchItem.item_url.string ?? ""
        item_type = Int16(launchItem.item_type.rawValue)
        
        // MARK: - UID
        uid = Int64(launchItem.uid)
        
        enrich()
        if let rpw = getpwuid(launchItem.uid) {
            self.uid_human = String(cString: rpw.pointee.pw_name)
        }
        
        // MARK: Plist
        guard launchItem.item_type == ES_BTM_ITEM_TYPE_AGENT || launchItem.item_type == ES_BTM_ITEM_TYPE_DAEMON else { return }
        var plistPath: String?
        if legacy {
            plistPath = item_path
        } else if let app_path = app_path {
            /// We need to resolve the relative plist path
            plistPath = URL(fileURLWithPath: app_path).appendingPathComponent(item_path).path
        }
        if let plistPath = plistPath {
            plist_contents = ProcessHelpers.getFileContents(at: plistPath)
        }
    }
}


// MARK: - Mac Monitor enrichment
extension LaunchItem: ESEnrichable {
    /// Derive the item type's name, the item's and the app's paths from their URLs, and the user's name if it's a
    /// system account.
    ///
    /// Not derived: the names of other users, and the plist's contents (read from this Mac).
    public mutating func enrich() {
        app_path = app_url.flatMap(URL.init(string:))?.path
        item_path = URL(string: item_url)?.path ?? ""
        uid_human = Process.userName(Int(uid), systemAccountsOnly: true) ?? uid_human
        switch es_btm_item_type_t(rawValue: UInt32(truncatingIfNeeded: item_type)) {
        case ES_BTM_ITEM_TYPE_USER_ITEM:
            item_type_string = "ES_BTM_ITEM_TYPE_USER_ITEM"
        case ES_BTM_ITEM_TYPE_APP:
            item_type_string = "ES_BTM_ITEM_TYPE_APP"
        case ES_BTM_ITEM_TYPE_AGENT:
            item_type_string = "ES_BTM_ITEM_TYPE_AGENT"
        case ES_BTM_ITEM_TYPE_DAEMON:
            item_type_string = "ES_BTM_ITEM_TYPE_DAEMON"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM:
            item_type_string = "ES_BTM_ITEM_TYPE_LOGIN_ITEM"
        default:
            item_type_string = "UNKNOWN"
        }
    }
}
