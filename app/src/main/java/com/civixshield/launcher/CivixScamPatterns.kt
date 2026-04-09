package com.civixshield.launcher

/**
 * CivixScamPatterns — India-Specific Offline Rules Engine (Unique Feature 1)
 *
 * A zero-latency, offline-first deterministic rules engine that pre-screens
 * notifications and call metadata before sending to Gemini AI.
 *
 * Tuned specifically for Indian scam patterns: Digital Arrest, UPI fraud,
 * fake government authority impersonation.
 *
 * Runs in <1ms on device. No internet required.
 * If preScore >= 40 → escalate to Gemini AI for deep analysis.
 */
object CivixScamPatterns {

    // ── Indian Authority Impersonation Keywords ──────────────────────────────
    // Scammers in India specifically abuse these institution names
    private val INDIAN_AUTHORITY_KEYWORDS = listOf(
        "CBI", "ED", "TRAI", "RBI", "Cyber Cell", "Supreme Court",
        "High Court", "Customs", "Income Tax", "NARCOTICS", "NCB",
        "FedEx", "DHL parcel", "money laundering", "arrest warrant",
        "IPS officer", "IRS officer", "Mumbai Police", "Delhi Police",
        "Enforcement Directorate", "Central Bureau"
    )

    // ── UPI / Banking Fraud Patterns ─────────────────────────────────────────
    // Fake UPI collect requests disguised as refunds or rewards
    private val UPI_FRAUD_PATTERNS = listOf(
        "collect request", "UPI PIN", "approve payment", "cashback credited",
        "KYC update", "link Aadhaar", "verify PAN", "SIM blocked",
        "OTP share", "re-KYC", "account blocked", "wallet suspended",
        "MPIN", "UPI request", "paytm wallet", "PhonePe request",
        "Google Pay collected", "BHIM UPI", "bank suspended", "NEFT failed"
    )

    // ── Digital Arrest Trigger Phrases ───────────────────────────────────────
    private val DIGITAL_ARREST_PHRASES = listOf(
        "do not disconnect", "stay on the call", "video call verification",
        "you are under observation", "legal action will be taken",
        "your account is frozen", "transfer to safe account",
        "digital arrest", "you are arrested", "warrant issued",
        "Supreme Court summons", "do not tell anyone", "keep this confidential",
        "police is outside your house", "you will be detained"
    )

    // ── Urgency Amplifiers (India-specific Hinglish) ─────────────────────────
    private val URGENCY_AMPLIFIERS = listOf(
        "turant", "abhi", "immediately", "2 ghante mein", "court order",
        "last warning", "final notice", "24 hours", "48 hours",
        "filhal", "urgent", "turant karein", "last chance",
        "jaldi karo", "kal subah tak"
    )

    // ── Social Engineering & Phishing Triggers ──────────────────────────────
    private val SOCIAL_ENGINEERING_PHRASES = listOf(
        "open this link", "click here", "visit", "verify now", "action required",
        "update now", "login to", "claim", "won", "prize", "gift card", "reward",
        "account restricted", "click below", "update your", "verify your"
    )

    // ── Phishing URL Patterns ────────────────────────────────────────────────
    private val PHISHING_URL_PATTERNS = listOf(
        "bit.ly", "tinyurl", "t.me", "wa.me", "rebrand.ly", "cutt.ly", "is.gd",
        "-secure-", "-verify-", "-login-", "secure-sbi", "rbi-alert",
        "paytm-kyc", "verify-pan", "aadhaar-update", "government-india",
        ".xyz", ".top", ".online", ".site", ".club", ".link", ".vip", ".today",
        "http://1", "http://2", "https://1", "https://2", // Detecting IP-based links
        "sbi.in", "rbi.in", "hdfc.in", "icici.in", "axis.in", "paytm.in" // Fake official domains
    )

    // ── Suspicious Sender Patterns ───────────────────────────────────────────
    private val SUSPICIOUS_SENDER_PATTERNS = listOf(
        "+1", "+44", "+92", "+86",   // Foreign numbers impersonating Indian agencies
        "VM-", "BP-",                // Fake bank SMS sender IDs
        "ALERTS", "OFFERS"           // Fake SMS gateway IDs
    )

    /**
     * Returns a pre-score (0–100) based purely on local rules.
     * This runs in <1ms on device with no internet needed.
     *
     * Score interpretation:
     *  0–14  → Safe, ignore silently
     * 15–39  → Low suspicion, log and monitor
     * 40–79  → HIGH — escalate to Gemini AI immediately
     * 80–100 → CRITICAL — auto-silence calls, show full-screen warning
     */
    fun preScore(text: String): Int {
        val lower = text.lowercase()
        var score = 0

        // ── Rule 1: Authority/UPI/Digital Arrest Keywords ────────────────────
        INDIAN_AUTHORITY_KEYWORDS.forEach { if (lower.contains(it.lowercase())) score += 20 }
        UPI_FRAUD_PATTERNS.forEach        { if (lower.contains(it.lowercase())) score += 15 }
        DIGITAL_ARREST_PHRASES.forEach    { if (lower.contains(it.lowercase())) score += 25 }
        URGENCY_AMPLIFIERS.forEach        { if (lower.contains(it.lowercase())) score += 10 }
        PHISHING_URL_PATTERNS.forEach     { if (lower.contains(it.lowercase())) score += 12 }
        SUSPICIOUS_SENDER_PATTERNS.forEach{ if (lower.contains(it.lowercase())) score +=  8 }
        SOCIAL_ENGINEERING_PHRASES.forEach{ if (lower.contains(it.lowercase())) score += 20 }

        // ── Rule 2: Advanced Link Analysis ───────────────────────────────────
        // Extract "raw" links that don't have http/https prefix
        val rawLinkRegex = "([a-zA-Z0-9-]+\\.[a-zA-Z]{2,6})".toRegex()
        val foundRawLinks = rawLinkRegex.findAll(lower).map { it.value }.toList()
        
        val hasLink = lower.contains("http://") || lower.contains("https://") || lower.contains("www.") || foundRawLinks.isNotEmpty()
        
        if (hasLink) {
            score += 20 // Base suspicion for any link

            // Brand Impersonation Check (e.g., sbi.in vs sbi.co.in)
            val brands = listOf("sbi", "rbi", "hdfc", "icici", "paytm", "kotak", "pnb")
            brands.forEach { brand ->
                // Use regex to ensure we catch the domain part (e.g., sbi.in, sbi-verify.com)
                val brandPattern = "$brand".toRegex()
                if (brandPattern.containsMatchIn(lower)) {
                    val isOfficial = lower.contains("$brand.co.in") || 
                                   lower.contains("$brand.org.in") || 
                                   lower.contains("$brand.com")
                    if (!isOfficial) {
                        score += 35 // Heavy penalty for unofficial brand links
                    }
                }
            }

            // Escalation: Link + Social Engineering command = Instant High Risk
            val hasCommand = SOCIAL_ENGINEERING_PHRASES.any { lower.contains(it.lowercase()) }
            if (hasCommand) {
                score += 25 // Significant boost if there's a "Click Here" style command
            }

            // Extra boost for suspicious TLDs or explicit phishing patterns
            PHISHING_URL_PATTERNS.forEach { if (lower.contains(it)) score += 15 }
        }

        return minOf(100, score)
    }

    fun isHighPriority(text: String)    = preScore(text) >= 40
    fun isCritical(text: String)        = preScore(text) >= 80
    fun isLowSuspicion(text: String)    = preScore(text) in 15..39

    /**
     * Returns a human-readable list of matched scam indicators for the UI.
     */
    fun getMatchedIndicators(text: String): List<String> {
        val lower = text.lowercase()
        val matched = mutableListOf<String>()

        INDIAN_AUTHORITY_KEYWORDS.forEach { if (lower.contains(it.lowercase())) matched.add("Authority Impersonation: $it") }
        UPI_FRAUD_PATTERNS.forEach        { if (lower.contains(it.lowercase())) matched.add("UPI/Banking Fraud: $it") }
        DIGITAL_ARREST_PHRASES.forEach    { if (lower.contains(it.lowercase())) matched.add("Digital Arrest Phrase: $it") }
        URGENCY_AMPLIFIERS.forEach        { if (lower.contains(it.lowercase())) matched.add("Urgency Amplifier: $it") }
        PHISHING_URL_PATTERNS.forEach     { if (lower.contains(it.lowercase())) matched.add("Phishing URL Pattern: $it") }

        return matched
    }
}
