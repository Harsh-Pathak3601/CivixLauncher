# CivixLauncher - Context Document

## Overview
**CivixLauncher** is the persistent background native Android sentinel of the CivixShield ecosystem. It is built using Kotlin and Jetpack Compose. Its primary role is to provide 24/7 real-time monitoring of notifications, clipboard activity, and phone calls to intercept and assess scam threats before they affect the user.

## Key Features & Responsibilities
- **Notification Monitoring:** Uses `NotificationListenerService` to monitor messaging apps (WhatsApp, Telegram, SMS), FinTech apps (Paytm, GPay), and email to detect fraud and scam patterns.
- **Live Call Screening & Monitoring:** Uses `CallScreeningService` to flag suspicious callers and `AccessibilityService` (Live Captions) to actively transcribe and monitor active calls.
- **Clipboard Sentinel:** Monitors copied text or links for known malicious signatures.
- **AI Integration:** Uses OpenRouter API leveraging the **Llama 3 8B** model to analyze transcripts and text for quick forensic reports and threat scoring.
- **Deep Link Integration:** Acts as a bridge, encoding threat metrics and pushing them to the main **CivixShieldApp** (React Native) via deep links (`civix://ingest`).
- **Data Storage:** stores data locally using native Android persistence mechanisms.

## Technical Stack
- **Language**: Kotlin
- **UI Toolkit**: Jetpack Compose
- **Architecture/Concurrency**: Coroutines & Flow
- **Background Processes**: Android Native Services (Accessibility, Call Screening, Notifications)
- **AI/Backend**: OpenRouter API, Local Storage

## Role in the Ecosystem
While the web app and main mobile app provide the primary user interfaces and detailed analysis dashboards, **CivixLauncher** is the silent engine on Android that gathers high-privilege system data (which standard cross-platform frameworks cannot easily access) to provide true real-time, proactive protection out of the box.
