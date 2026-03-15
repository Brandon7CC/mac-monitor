# Mac Monitor Architecture

## Overview

Mac Monitor is a macOS security monitoring tool built on Apple's Endpoint Security (ES) and System Extension APIs. The architecture is designed for high-performance event ingestion with constant memory usage regardless of event count.

## Core Components

### 1. Security Extension (`com.swiftlydetecting.agent.securityextension`)
- Runs as a privileged System Extension
- Subscribes to Endpoint Security events
- Performs initial event modeling and enrichment
- Sends events to the agent app via XPC

### 2. Agent App (`Mac Monitor.app`)
- Main user interface
- Receives events from Security Extension via XPC
- Stores events in memory-mapped binary log
- Provides filtering, correlation, and analysis features

### 3. SutroESFramework
- Shared framework containing:
  - Event models (`Message`, `Process`, `EventType`)
  - EventStore (memory-mapped event storage)
  - MMapEventLog (binary log implementation)
  - EndpointSecurityManager (XPC and ES client management)

---

## Memory Management for Event Storage

### Design Goals

1. **Constant RAM Usage (storage layer)**: Event storage should not keep full decoded event payloads in RAM
2. **High Throughput**: Sustain high-rate ingest with batched writes and publish coalescing
3. **Fast Filtering**: Filter events without decoding full event data
4. **Lazy Decode**: Only decode events when needed for display

### Architecture: Index + MMAP Backing

```
┌─────────────────────────────────────────────────────────────────┐
│                         EventStore                               │
├─────────────────────────────────────────────────────────────────┤
│  In-Memory Index (RAM)                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ EventIndexEntry (~100 bytes each)                        │    │
│  │  - id: UUID                     - mmapOffset: Int        │    │
│  │  - machTime: Int64              - eventType: Int         │    │
│  │  - darwinTime: Date             - esEventType: String    │    │
│  │  - auditTokenString: String     - executablePathHash: UInt64  │
│  │  - parentAuditTokenString: String                       │    │
│  │  - targetPathHash: UInt64?       - euidHuman: String?    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Secondary Indices (for O(1) lookups)                           │
│  - eventIDIndex: [UUID: Int]                                    │
│  - targetAuditTokenIndex: [String: [Int]]                       │
│  - processGroupIndex: [Int32: [Int]]                            │
│  - sessionGroupIndex: [Int32: [Int]]                            │
│  - correlatedChildren: [Int: [Int]]                             │
│  - pathHashLookup: [UInt64: String]                             │
├─────────────────────────────────────────────────────────────────┤
│                        MMapEventLog                              │
│  Memory-mapped file (OS manages paging)                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Header (64 bytes)                                        │    │
│  │  - magic: UInt32 ("MMLG")                               │    │
│  │  - version: UInt32                                       │    │
│  │  - eventCount: UInt64                                    │    │
│  │  - dataOffset: UInt64                                    │    │
│  ├─────────────────────────────────────────────────────────┤    │
│  │ Event Records (variable length)                          │    │
│  │  - length: UInt32                                        │    │
│  │  - payload: [UInt8] (PropertyList binary encoded Message)│    │
│  │  ... repeated ...                                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  File: ~/Library/Application Support/                           │
│        com.swiftlydetecting.agent/event_log/events.mmap         │
└─────────────────────────────────────────────────────────────────┘
```

### Memory Footprint

| Component | Size per Event | 10K Events | 100K Events | 1M Events |
|-----------|---------------|------------|-------------|-----------|
| EventIndexEntry | ~100 bytes | 1 MB | 10 MB | 100 MB |
| Secondary Indices | ~50 bytes | 0.5 MB | 5 MB | 50 MB |
| **Total RAM** | **~150 bytes** | **1.5 MB** | **15 MB** | **150 MB** |
| MMAP File (disk) | ~1-2 KB | 10-20 MB | 100-200 MB | 1-2 GB |

**Key Insight**: Full `Message` objects (~1-2 KB each) are stored on disk in the MMAP file. The OS pages in only the portions of the file that are actively accessed.

### Event Ingestion Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Security         │     │ Event Buffer     │     │ EventStore       │
│ Extension        │────▶│ (RAM, throttled) │────▶│ (Index + MMAP)   │
│ (ES callback)    │ XPC │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                │                         │
                                │ Batch: 2000-4000        │
                                │ Interval: 100-1500ms    │
                                │ (dynamic throttle)      │
                                ▼                         ▼
                         ThrottleManager           Index + Append
                         (rate-based adjustment)   (batch MMAP write)
```

### Throttling Strategy

The `ThrottleManager` dynamically adjusts batch intervals based on event rate:

| Event Rate | Batch Size | Flush Interval |
|------------|------------|----------------|
| < 1000/sec | 2000 | 100ms |
| 1000-2000/sec | 3000 | ~500ms |
| > 2000/sec | 4000 | up to 1500ms |

This prevents the UI from being overwhelmed during bursty event activity.

### Incremental Filtering

When new events arrive, the UI performs **incremental filtering**:

1. **Track `lastProcessedIndex`**: Only filter NEW events, not all events
2. **Index-first pass**: Apply filter predicates against `EventIndexEntry` values
3. **Decode only filtered delta**: Decode only matching new indices (`getEventsWindow`)
4. **Append to caches**: Reuse existing filtered display arrays

```
Full Recompute (filter change):
  lastProcessedIndex = 0
  Filter ALL events → Decode ALL filtered events

Incremental (new events):
  Filter events[lastProcessedIndex...] → Decode NEW filtered events
  Append to existing caches
```

### Lazy Decode Flow

```
┌─────────────────┐
│ User scrolls /  │
│ filter changes  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Filter Index    │────▶│ Get filtered    │
│ (in-memory,     │     │ indices         │
│ no decode)      │     └────────┬────────┘
└─────────────────┘              │
                                 ▼
                    ┌────────────────────────┐
                    │ getEventsWindow()      │
                    │ Decode only indices    │
                    │ in display window      │
                    └────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ Message objects        │
                    │ (full decoded events)  │
                    │ for table display      │
                    └────────────────────────┘
```

### Thread Safety

| Component | Queue | Access Pattern |
|-----------|-------|----------------|
| EventStore.index | storeQueue (concurrent) | Read: `.sync`, Write: `.async(flags: .barrier)` |
| MMapEventLog writes | writeQueue (serial) | All access serialized |
| Event buffer | eventBufferQueue (serial) | All access serialized |
| UI state updates | DispatchQueue.main | All `@Published` updates |

### Data Retention

- **Session-based**: MMAP file is cleared on app launch (`mmapLog.reset()`)
- **No persistence between sessions**: Fresh start each launch
- **Clear on demand**: User can clear events via UI

### Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Insert batch of N events | O(N) | Batch MMAP write + index build |
| Filter events (incremental) | O(N_new) | Only new events processed |
| Filter events (full recompute) | O(N_total) | All events processed |
| Decode event for display | O(1) | Single MMAP read |
| Lookup event by ID | O(1) | UUID → index dictionary |
| Find parent process | O(1) amortized | audit_token → index dictionary |
| Get correlated events | O(1) lookup + O(k) decode | k = number of children |

### Future Improvements

1. **Persistent Index**: Save index to disk for faster app launch with existing events
2. **Windowed Decoding**: Only decode events visible in table viewport (true virtual scrolling)
3. **Compression**: Compress MMAP file to reduce disk usage
4. **Event Pruning**: Allow users to delete old events to manage disk space

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Mac Monitor.app                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                        UI Layer (SwiftUI)                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐    │  │
│  │  │ EventView   │  │ FilterView  │  │ Event Facts Windows     │    │  │
│  │  │ (tables)    │  │             │  │                         │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                  │                                       │
│                                  ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    SutroESFramework                                │  │
│  │  ┌───────────────────┐  ┌───────────────────┐                     │  │
│  │  │ EventStore        │  │ EndpointSecurity  │                     │  │
│  │  │ (Index + MMAP)    │  │ Manager           │                     │  │
│  │  │                   │◄─┤ (XPC + Batching)  │                     │  │
│  │  └───────────────────┘  └───────────────────┘                     │  │
│  │           │                       │                                │  │
│  │           ▼                       ▼                                │  │
│  │  ┌───────────────────┐  ┌───────────────────┐                     │  │
│  │  │ MMapEventLog      │  │ XPC Connection    │                     │  │
│  │  │ (Binary Log)      │  │                   │                     │  │
│  │  └───────────────────┘  └───────────────────┘                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                  │                                       │
└──────────────────────────────────│───────────────────────────────────────┘
                                   │ XPC
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    Security Extension (System Extension)                  │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │ Endpoint Security Client                                           │   │
│  │  - es_new_client()                                                 │   │
│  │  - es_subscribe()                                                  │   │
│  │  - Event callback → Model → Binary encode → XPC send              │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  Runs as a privileged system extension process (user space)               │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Related Files

| File | Purpose |
|------|---------|
| `SutroESFramework/EventStore/EventStore.swift` | Main event store with index and MMAP lazy decode |
| `SutroESFramework/EventStore/MMapEventLog.swift` | Memory-mapped binary log implementation |
| `SutroESFramework/ESM/ESManager.swift` | XPC connection, event batching, throttling |
| `SutroESFramework/Core Data Controller/ThrottleManager.swift` | Dynamic batch interval adjustment |
| `ProjectSutro/Main App View/ContentView.swift` | UI with incremental filtering |
| `SutroESFramework/Events/Models/Message.swift` | Event model (Codable for MMAP storage) |

---

## Performance Test Workflow

Mac Monitor includes an automated UI stress harness designed for iterative tuning:

- `ProjectSutro/ProjectSutro/Debug/StressTestRunner.swift` injects fixture-backed events at a controlled rate.
- `ProjectSutro/ProjectSutro/Debug/MainThreadMonitor.swift` samples main-thread responsiveness.
- `ProjectSutro/ProjectSutroUITests/StressTestUITests.swift` reads JSON results and enforces thresholds.

Threshold model:

- **Guardrails**: CI-enforced to catch catastrophic regressions.
- **Targets**: Strict optimization goals reported in output (non-fatal while tuning).

Recommended runs:

- Fast smoke: `xcodebuild -project ProjectSutro.xcodeproj -scheme ProjectSutro -destination 'platform=macOS' -only-testing:'ProjectSutroUITests/StressTestUITests/testSmokeStress1000' test`
- Baseline: `xcodebuild -project ProjectSutro.xcodeproj -scheme ProjectSutro -destination 'platform=macOS' -only-testing:'ProjectSutroUITests/StressTestUITests/testBaselineStress5000' test`
- Full suite (includes long scenarios): set `STRESS_FULL_SUITE=1` then run full `StressTestUITests` class.
