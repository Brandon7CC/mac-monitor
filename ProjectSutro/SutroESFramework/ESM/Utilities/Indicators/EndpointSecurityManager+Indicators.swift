//
//  EndpointSecurityManager+Indicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Mac Monitor's connection
public extension EndpointSecurityManager {
    /// Sends indicator requests over Mac Monitor's own connection to the Security Extension, so it knows Mac Monitor
    /// as the app that owns the event stream, or not (``IndicatorEngine/connect(_:changes:)``). A request waits until
    /// the Security Extension running now has said it answers them (``SensorSupport``). One that doesn't is sent
    /// nothing, and the request has no reply. One that stops answering is asked again before the next request.
    var indicatorTransport: IndicatorEngine.Transport {
        { [weak self] request, reply in
            guard let self else { return DispatchQueue.main.async { reply(nil) } }
            let sensor = sensor
            indicatorSupport.send({ answer in
                sensor.call { $0.indicators(request, reply: $1) } completion: { answer($0) }
            }, completion: reply)
        }
    }

    /// Ask the Security Extension running now for its indicators on a connection of its own
    /// (``SensorClient/probe(caller:_:completion:)``), for ``indicatorSupport``.
    ///
    /// - Parameter answered: Called on the main queue: `true` when it replied with a set.
    internal func probeIndicators(_ answered: @escaping (Bool) -> Void) {
        sensor.probe { $0.indicators(IndicatorRequest(.list).encoded(), reply: $1) } completion: { data in
            answered(data.flatMap(IndicatorReply.decode) != nil)
        }
    }
}
