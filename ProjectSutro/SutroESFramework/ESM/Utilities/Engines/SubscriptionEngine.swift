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
    /// Ask the Security Extension what it's subscribed to, and keep its answer in ``monitoredEventStrings``. A
    /// request that fails leaves what's known as it is.
    public func requestEventSubscriptions() {
        sensor.call { $0.eventSubscriptions(reply: $1) } completion: { response in
            guard let response else { return }
            self.monitoredEventStrings = Set(response)
            self.hasEventSubscriptions = true
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
    ///   - completion: On main, `true` if the Security Extension did it, `false` if it refused, or `nil` if it didn't
    ///     answer.
    public func setSubscription(_ eventString: String, enabled: Bool,
                                completion: @escaping (Bool?) -> Void = { _ in }) {
        sensor.call({ $0.setSubscription(eventString, enabled: enabled, reply: $1) }, completion: completion)
    }
    
    /// Put every field filter back to its default (``defaultFieldFilters``).
    ///
    /// - Parameter completion: On main, `true` if the Security Extension applied every default filter: `false` from
    ///   one older than 3.1.0, or without capture.
    public func resetFieldFilters(completion: @escaping (Bool) -> Void) {
        var pending = FieldFilter.allCases.count, appliesAll = true
        for filter in FieldFilter.allCases {
            let enabled = defaultFieldFilters.contains(filter)
            setSubscription(filter.rawValue, enabled: enabled) { applied in
                if enabled { appliesAll = appliesAll && applied == true }
                pending -= 1
                if pending == 0 { completion(appliesAll) }
            }
        }
    }
}


// MARK: - Refusals
extension NewClientResult {
    /// What Settings says when another Mac Monitor owns the event stream, so this one's change was refused.
    public static let streamOwnedSentence = "Another Mac Monitor owns the event stream, so only it can change this."

    /// Why the Security Extension refused to turn an enrichment switch on or off. With an answer, the reason follows
    /// this Mac Monitor's handshake. A refusal while capture runs for it is the switch's own reason, such as the
    /// kernel's network statistics. Otherwise another Mac Monitor owns the event stream, or capture isn't running.
    /// With no answer, the Security Extension isn't running, whatever the last handshake said.
    ///
    /// - Parameters:
    ///   - answered: Did the Security Extension answer the request?
    ///   - onThisMac: What stops the switch while capture runs, or `nil` for a switch only a stopping capture refuses.
    /// - Returns: The sentence Settings > General shows under the switch.
    public func refusal(answered: Bool, onThisMac: String?) -> String {
        let notRunning = "Mac Monitor can't record yet, so nothing changed."
        switch answered ? self : .waiting {
        case .success: return onThisMac ?? notRunning
        case .streamOwned: return Self.streamOwnedSentence
        default: return notRunning
        }
    }
}
