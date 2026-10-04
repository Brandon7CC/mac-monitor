//
//  SubscriptionEngine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import OSLog


// MARK: - Event subscription operations
/// Extension of the ESM which enables dynamic event subscriptions at the ES level.
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
    
    
    // MARK: - Sensor Context
    
    public func seGetEventSubscriptionsAsString() -> Set<String> {
        return Set(self.monitoredEvents.map { eventTypeToString(from: $0) })
    }
    
    // MARK: Step #3 in (un)subscribing from an ES event
    /// Subscribe to, or unsubscribe from, a single event type on the ES client.
    ///
    /// - Parameters:
    ///   - event: The `ES_EVENT_TYPE_*` name.
    ///   - enabled: `true` to subscribe, `false` to unsubscribe.
    /// - Returns: `true` if Endpoint Security accepted the request.
    @discardableResult
    public func setEventSubscription(_ event: String, enabled: Bool) -> Bool {
        guard let esClient = self.esClient else {
            os_log("There is no endpoint security client to submit this subscription request to!")
            return false
        }
        guard !event.isEmpty else { return false }
        
        let eventType: es_event_type_t = eventStringToType(from: event)
        let request: es_return_t = enabled ? es_subscribe(esClient, [eventType], 1) : es_unsubscribe(esClient, [eventType], 1)
        guard request == ES_RETURN_SUCCESS else {
            os_log("Error \(enabled ? "subscribing to" : "unsubscribing from"): \(event)")
            return false
        }
        
        if enabled {
            if !self.monitoredEvents.contains(eventType) { self.monitoredEvents.append(eventType) }
            self.monitoredEventStrings.insert(event)
        } else {
            self.monitoredEvents.removeAll { $0 == eventType }
            self.monitoredEventStrings.remove(event)
        }
        return true
    }
}
