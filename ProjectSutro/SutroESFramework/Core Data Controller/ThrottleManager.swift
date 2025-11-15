//
//  ThrottleManager.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/23/23.
//

import Foundation

/// Overview
/// - Tracks events per second using a sliding window approach
/// - Gradually increases save interval when event rate exceeds threshold
/// - Slowly decreases interval when event rate normalizes (recovery)
/// - Thread-safe using concurrent queue with barrier flags for writes
///
class ThrottleManager {
    private var eventRateCounter: Int = 0
    private var eventTimestamp: Date = Date()
    
    private let heavyFlowRate: Double = 1000
    private let throttleFactor: Double = 0.001
    private let minSaveInterval: Double = 0.1
    private let maxSaveInterval: Double = 1.5
    private let deThrottleRate: Double = 0.1
    
    private var _saveInterval: Double = 0.1
    private let queue = DispatchQueue(label: "com.swiftlydetecting.throttle", attributes: .concurrent)

    var eventRate: Double {
        queue.sync {
            let elapsedTime = Date().timeIntervalSince(eventTimestamp)
            return elapsedTime > 0 ? Double(eventRateCounter) / elapsedTime : 0
        }
    }
    
    var saveInterval: Double {
        queue.sync { _saveInterval }
    }
    
    func registerEvent() {
        queue.async(flags: .barrier) {
            self.eventRateCounter += 1
            let elapsedTime = Date().timeIntervalSince(self.eventTimestamp)
            
            if elapsedTime >= 1.0 {
                self.adjustSaveInterval(eventRate: Double(self.eventRateCounter) / elapsedTime)
                self.eventRateCounter = 0
                self.eventTimestamp = Date()
            }
        }
    }
    
    private func adjustSaveInterval(eventRate: Double) {
        if eventRate >= heavyFlowRate {
            let dynamicThrottleRate = throttleFactor * (eventRate - heavyFlowRate)
            _saveInterval = min(_saveInterval + dynamicThrottleRate, maxSaveInterval)
        } else if _saveInterval > minSaveInterval {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                guard let self = self else { return }
                self.queue.async(flags: .barrier) {
                    self._saveInterval = max(self._saveInterval - self.deThrottleRate, self.minSaveInterval)
                }
            }
        }
    }
}
