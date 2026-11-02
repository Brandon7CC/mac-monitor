//
//  SubscriptionEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import OSLog


// MARK: - Event subscription operations
/// Extension of the ESM which asks the Security Extension to change its event subscriptions (agent context).
///
/// **Functionality Covers:**
///   - Getting the event subscriptions
///   - Subscribing to an event
///   - Unsubscribing from an event
///
extension EndpointSecurityManager {
    // MARK: - Agent Context
    
    // MARK: Step #1 in getting the list of events we're subscribed to from Endpoint Security
    public func requestEventSubscriptions() {
        sensor.call { $0.eventSubscriptions(reply: $1) } completion: { response in
            guard let response else { return }
            self.monitoredEventStrings = Set(response)
        }
    }
    
    public func getCoreEvents() -> [String] {
        return defaultEventSubscriptions.map { eventTypeToString(from: $0) }
    }
    
    // MARK: Step #2 in subscribing to or unsubscribing from ES events
    /// Ask the Security Extension to subscribe to an event, or unsubscribe from it.
    ///
    /// - Parameters:
    ///   - eventString: The event's `ES_EVENT_TYPE_*` name.
    ///   - enabled: Subscribe (`true`) or unsubscribe (`false`).
    public func setSubscription(_ eventString: String, enabled: Bool) {
        sensor.call { $0.setSubscription(eventString, enabled: enabled, reply: $1) }
    }
}
