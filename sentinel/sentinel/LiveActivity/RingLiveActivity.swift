// RingLiveActivity.swift
//
// This file previously contained a duplicate Widget + Lock Screen implementation
// that mirrored RingWidgets/RingWidgetsLiveActivity.swift.
//
// Consolidated: all Live Activity UI now lives exclusively in the widget extension:
//   ring/RingWidgets/RingWidgetsLiveActivity.swift
//
// Shared data model used by both targets:
//   ring/ring/LiveActivity/RingActivityAttributes.swift
//
// The main app target references RingActivityAttributes (from the file above) via
// LiveActivityManager.swift — no Widget conformance is needed here.
