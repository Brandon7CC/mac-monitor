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
///   - Turning field filters on and off, and back to their defaults
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
    
    /// Mac Monitor's default subscriptions, for Reset Subscriptions.
    ///
    /// - Parameter appliesFieldFilters: Can the Security Extension apply field filters
    ///   (``resetFieldFilters(completion:)``)? If not, the defaults leave out the events that are default only with a
    ///   filter, such as close.
    /// - Returns: `ES_EVENT_TYPE_*` names.
    public func getCoreEvents(appliesFieldFilters: Bool = true) -> [String] {
        (appliesFieldFilters ? defaultEventSubscriptions : defaultEventSubscriptionsWithoutFieldFilters)
            .map { eventTypeToString(from: $0) }
    }
    
    // MARK: Step #2 in subscribing to or unsubscribing from ES events
    /// Ask the Security Extension to subscribe to an event, or unsubscribe from it, or to turn a field filter on or
    /// off.
    ///
    /// - Parameters:
    ///   - eventString: The event's `ES_EVENT_TYPE_*` name, or a ``FieldFilter`` wire name.
    ///   - enabled: Subscribe or turn on (`true`), or unsubscribe or turn off (`false`).
    ///   - completion: On main, `true` if the Security Extension did it.
    public func setSubscription(_ eventString: String, enabled: Bool,
                                completion: @escaping (Bool) -> Void = { _ in }) {
        sensor.call { $0.setSubscription(eventString, enabled: enabled, reply: $1) } completion: {
            completion($0 ?? false)
        }
    }
    
    /// Put every field filter back to its default (``defaultFieldFilters``).
    ///
    /// - Parameter completion: On main, `true` if the Security Extension applied every default filter: `false` from
    ///   one older than 3.0.1, or without capture.
    public func resetFieldFilters(completion: @escaping (Bool) -> Void) {
        var pending = FieldFilter.allCases.count, appliesAll = true
        for filter in FieldFilter.allCases {
            let enabled = defaultFieldFilters.contains(filter)
            setSubscription(filter.rawValue, enabled: enabled) { applied in
                if enabled { appliesAll = appliesAll && applied }
                pending -= 1
                if pending == 0 { completion(appliesAll) }
            }
        }
    }
}
