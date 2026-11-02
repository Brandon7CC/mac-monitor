//
//  ESTranslation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/10/22.
//

import Foundation
import EndpointSecurity
import OSLog


private let dateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss.SSS"
    return formatter
}()


public func eventTimeStamp(for message: ESMessage) -> String {
    message.message_darwin_time.map(dateFormatter.string(from:)) ?? "Unknown timestamp"
}


/// The SF Symbol an event shows, from ``ModeledEvent/symbols``.
///
/// - Parameter eventString: The event type's `ESTypes.h` name, such as `ES_EVENT_TYPE_NOTIFY_EXEC`.
/// - Returns: Its symbol, or `questionmark.app.dashed` for an event without one.
public func eventStringToImage(from eventString: String) -> String {
    if let symbol = ModeledEvent.symbols[eventString] { return symbol }
    os_log("❌ Unknown image for event: \(eventString)")
    return "questionmark.app.dashed"
}


// MARK: - ES muting
/// `es_mute_path_type_t`: how a muted path matches.
private let muteTypeNames = ConstantNames([
    ES_MUTE_PATH_TYPE_PREFIX.rawValue: "ES_MUTE_PATH_TYPE_PREFIX",
    ES_MUTE_PATH_TYPE_LITERAL.rawValue: "ES_MUTE_PATH_TYPE_LITERAL",
    ES_MUTE_PATH_TYPE_TARGET_PREFIX.rawValue: "ES_MUTE_PATH_TYPE_TARGET_PREFIX",
    ES_MUTE_PATH_TYPE_TARGET_LITERAL.rawValue: "ES_MUTE_PATH_TYPE_TARGET_LITERAL",
], unknown: "ES_MUTE_PATH_TYPE_TARGET_PREFIX")

/// A mute path type's name, as mute files and `macmonitor mute` spell it.
///
/// - Parameter muteType: The type.
/// - Returns: Its name, or `ES_MUTE_PATH_TYPE_TARGET_PREFIX` for any other value.
public func getMuteCaseString(muteType: es_mute_path_type_t) -> String {
    muteTypeNames.name(of: Int(muteType.rawValue))
}
