package com.civixshield.launcher

import com.google.firebase.Timestamp
import com.google.firebase.firestore.ktx.firestore
import com.google.firebase.ktx.Firebase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * CivixFirestoreVault — Cloud Threat Sync (Unique Feature 4)
 *
 * Saves every intercepted threat to the SAME Firestore /analyses collection
 * that the CivixShield Next.js web app uses via /api/analyze.
 *
 * No SQLite. No Room. No extra database setup.
 * Threats caught on the phone appear instantly on the web dashboard.
 * High-risk threats (score > 60) auto-publish to the Community Feed.
 */
object CivixFirestoreVault {

    /**
     * Saves an intercepted threat to Firestore /analyses collection.
     * Document structure matches the existing schema from /api/analyze route.
     *
     * @param sourceType  "SMS" or "CALL"
     * @param sourceApp   Package name (com.whatsapp) or caller number (+91XXXXXXXXXX)
     * @param content     The intercepted message or call metadata
     * @param preScore    Local pre-score from CivixScamPatterns (0–100)
     */
    fun saveThreat(
        sourceType: String,
        sourceApp: String,
        content: String,
        preScore: Int
    ) {
        val db = Firebase.firestore

        // Map score to risk_level — matches web app's enum
        val riskLevel = when {
            preScore >= 80 -> "critical"
            preScore >= 50 -> "high"
            preScore >= 30 -> "medium"
            else           -> "low"
        }

        // Get human-readable matched indicators for display
        val indicators = CivixScamPatterns.getMatchedIndicators(content)

        // Document structure matches the existing /analyses Firestore schema
        val threat = hashMapOf(
            "user_id"         to "civix_launcher",      // Tags this as coming from native launcher
            "content_type"    to sourceType,             // "SMS" or "CALL"
            "content"         to content,                // The intercepted text
            "source_app"      to sourceApp,              // App package or caller number
            "risk_score"      to preScore,               // Local pre-score (0–100)
            "risk_level"      to riskLevel,              // "low" | "medium" | "high" | "critical"
            "intercepted_by"  to "CivixLauncher",        // Unique tag for launcher-sourced entries
            "scam_patterns"   to indicators.ifEmpty { listOf("Intercepted by CivixLauncher") },
            "is_suspicious"   to (preScore > 50),
            "red_flags"       to indicators,
            "created_at"      to Timestamp.now()
        )

        CoroutineScope(Dispatchers.IO).launch {
            db.collection("analyses")
                .add(threat)
                .addOnSuccessListener { docRef ->
                    android.util.Log.d(
                        "CivixLauncher",
                        "✅ Threat saved → Firestore: ${docRef.id} | Score: $preScore | Type: $sourceType"
                    )
                    // If risk_score > 60 → auto-shared to community_scams (handled server-side)
                }
                .addOnFailureListener { e ->
                    android.util.Log.e("CivixLauncher", "❌ Firestore save failed: ${e.message}")
                }
        }
    }
}
