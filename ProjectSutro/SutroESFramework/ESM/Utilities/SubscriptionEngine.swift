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
    
    public func getSimpleEventSubscriptions() -> [String] {
        return Array(self.monitoredEventStrings.sorted(by: <))
    }
    
    public func getCoreEvents() -> [String] {
        return defaultEventSubscriptions.map { eventTypeToString(from: $0) }
    }
    
    // MARK: Step #2 in unsubscribing from events
    // @note send across events that should be unsubscribed from by the Endpoint Security client
    public func puntEventToUnsubscribe(eventString: String) {
        sensor.call { $0.setSubscription(eventString, enabled: false, reply: $1) }
    }
    
    // MARK: Step #2 in subscribing to ES events
    // @note send across events that we should subscrube to
    public func puntEventToSubscribe(eventString: String) {
        sensor.call { $0.setSubscription(eventString, enabled: true, reply: $1) }
    }
}
