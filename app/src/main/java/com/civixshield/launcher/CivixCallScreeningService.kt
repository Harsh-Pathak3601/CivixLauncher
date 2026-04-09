package com.civixshield.launcher

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import androidx.core.app.NotificationCompat

class CivixCallScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        val callerNumber   = callDetails.handle?.schemeSpecificPart ?: "Unknown"
        val callDirection  = callDetails.callDirection

        // Only screen incoming calls
        if (callDirection != Call.Details.DIRECTION_INCOMING) {
            respondToCall(callDetails, CallResponse.Builder().setDisallowCall(false).build())
            return
        }

        // Build metadata string for Gemini to analyze
        val matchedIndicators = CivixScamPatterns.getMatchedIndicators(callerNumber)
        val callMetadata = """
            INCOMING_CALL_DETECTED
            Caller: $callerNumber
            Direction: INCOMING
            State: RINGING
            
            [CivixShield Analysis]
            Indicators: ${matchedIndicators.joinToString(", ")}
            Source: Live Call Screening
        """.trimIndent()

        // ── Step 1: Run India-specific local pre-screen ──
        // We also check the caller number itself for suspicious patterns
        val preScore = CivixScamPatterns.preScore(callerNumber) + 10 // Base suspicion for screened calls

        // DEBUG LOGGING
        android.util.Log.d("CivixLauncher", "Incoming call from $callerNumber. Scam Score: $preScore")

        // ALWAYS save to Firestore for visibility during testing
        CivixFirestoreVault.saveThreat(
            sourceType = "CALL",
            sourceApp  = callerNumber,
            content    = callMetadata,
            preScore   = preScore
        )

        // ── Step 3: Increment call screening counter on home screen ──────────
        incrementCallCounter()

        // ── Step 4: Forward to CivixShield app for Gemini AI analysis ────────
        forwardCallToCivix(callerNumber, callMetadata, preScore)

        // ── Step 5: Auto-silence if score is CRITICAL (Unique Feature 3) ─────
        // This does NOT reject the call — user can still answer it.
        // Phone vibrates silently while CivixShield displays the scam warning.
        val silenceCall = preScore >= 80

        respondToCall(callDetails, CallResponse.Builder()
            .setDisallowCall(false)
            .setRejectCall(false)
            .setSilenceCall(silenceCall)   // ← Auto-silence on critical threat
            .setSkipCallLog(false)
            .build()
        )
    }

    private fun incrementCallCounter() {
        val prefs   = applicationContext.getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
        val current = prefs.getInt("calls_screened", 0)
        prefs.edit().putInt("calls_screened", current + 1).apply()
    }

    private fun forwardCallToCivix(callerNumber: String, metadata: String, score: Int) {
        // Use Uri.Builder.appendQueryParameter() — encodes query values exactly once.
        // The old manual double-encode produced broken %25XX sequences that crashed Expo Router.
        val deepLink = Uri.parse("civix://ingest").buildUpon()
            .appendQueryParameter("sourcetype", "CALL")
            .appendQueryParameter("label", callerNumber)
            .appendQueryParameter("content", metadata)
            .appendQueryParameter("score", score.toString())
            .build().toString()

        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            `package` = "com.civixshield.app"
        }

        var delivered = false
        try {
            applicationContext.startActivity(intent)
            delivered = true
            android.util.Log.d("CivixLauncher", "✅ Call deep link delivered to CivixShieldApp")
        } catch (e: Exception) {
            android.util.Log.w("CivixLauncher",
                "CivixShield app not found. Call deep link dropped. Error: ${e.message}")
        }

        if (!delivered) {
            showFallbackNotification("CALL", callerNumber, metadata, deepLink)
        }
    }

    private fun showFallbackNotification(
        sourceType: String, label: String, content: String, deepLink: String
    ) {
        val channelId = "civix_threats"
        val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "CivixShield Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            nm.createNotificationChannel(channel)
        }

        val tapIntent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            `package` = "com.civixshield.app"
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val shortContent = if (content.length > 80) content.take(80) + "…" else content
        val notification = NotificationCompat.Builder(applicationContext, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠️ CivixShield — $sourceType Intercepted")
            .setContentText("From: $label")
            .setStyle(NotificationCompat.BigTextStyle().bigText("From: $label\n\n$shortContent"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify(System.currentTimeMillis().toInt(), notification)
    }
}
