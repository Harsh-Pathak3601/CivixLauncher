package com.civixshield.launcher

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*

/**
 * CivixClipboardMonitor — Real-Time Clipboard Link Scanner (Unique Feature 5)
 *
 * When a user copies any link (from WhatsApp, Instagram, SMS, etc.),
 * CivixLauncher silently checks it in the background using CivixScamPatterns.
 *
 * If it looks malicious, a toast warning fires BEFORE the user pastes it anywhere.
 *
 * WHY THIS IS UNIQUE: No launcher or security app in India currently offers
 * real-time clipboard link scanning as a background service. This covers the
 * massive gap where scam links spread via WhatsApp "forward" messages.
 *
 * Usage: Call startMonitoring() from MainActivity.onCreate()
 */
class CivixClipboardMonitor(private val context: Context) {

    private val scope       = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var lastChecked = ""

    fun startMonitoring() {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        clipboard.addPrimaryClipChangedListener {
            val clip = clipboard.primaryClip ?: return@addPrimaryClipChangedListener
            val text = clip.getItemAt(0)?.text?.toString() ?: return@addPrimaryClipChangedListener

            // Avoid re-checking the same content
            if (text == lastChecked || text.isBlank()) return@addPrimaryClipChangedListener
            lastChecked = text

            // Only check if it looks like a URL or contains keywords
            val looksLikeUrl = text.contains("http") || text.contains("www.")
            val hasSuspiciousKeyword = CivixScamPatterns.preScore(text) >= 15

            if (!looksLikeUrl && !hasSuspiciousKeyword) return@addPrimaryClipChangedListener

            scope.launch {
                val preScore   = CivixScamPatterns.preScore(text)
                val indicators = CivixScamPatterns.getMatchedIndicators(text)

                if (preScore >= 30) {
                    withContext(Dispatchers.Main) {
                        val msg = buildString {
                            append("⚠️ CivixShield: Suspicious content detected!\n")
                            append("Risk Score: $preScore/100\n")
                            if (indicators.isNotEmpty()) {
                                append("Flags: ${indicators.first()}")
                            }
                        }

                        Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                    }

                    // Also save clipboard threat to Firestore vault
                    CivixFirestoreVault.saveThreat(
                        sourceType = "URL", // Clipboard is mostly URLs
                        sourceApp  = "clipboard",
                        content    = text,
                        preScore   = preScore
                    )

                    // Forward to CivixShieldApp so it shows up in Recent Activity
                    forwardToCivixShield("URL", "clipboard", text)
                }
            }
        }
    }

    fun stopMonitoring() {
        scope.cancel()
    }

    private fun forwardToCivixShield(sourceType: String, label: String, content: String) {
        // Use Uri.Builder.appendQueryParameter() — Android encodes query values exactly once.
        // Manual string concatenation or double-encoding causes Expo Router's
        // decodeURIComponent to crash on malformed '%' sequences.
        val deepLink = Uri.parse("civix://ingest").buildUpon()
            .appendQueryParameter("sourcetype", sourceType)
            .appendQueryParameter("label", label)
            .appendQueryParameter("content", content)
            .build().toString()

        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            `package` = "com.civixshield.app"
        }

        var delivered = false
        try {
            context.startActivity(intent)
            delivered = true
            android.util.Log.d("CivixLauncher", "✅ Clipboard deep link delivered to CivixShieldApp")
        } catch (e: Exception) {
            android.util.Log.w("CivixLauncher",
                "CivixShield app not found. Clipboard deep link dropped. Error: ${e.message}")
        }

        if (!delivered) {
            showFallbackNotification(sourceType, label, content, deepLink)
        }
    }

    private fun showFallbackNotification(
        sourceType: String, label: String, content: String, deepLink: String
    ) {
        val channelId = "civix_threats"
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

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
            context, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val shortContent = if (content.length > 80) content.take(80) + "…" else content
        val notification = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠️ CivixShield — Malicious Link Copied")
            .setContentText("Check before you paste!")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Content:\n$shortContent"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify(System.currentTimeMillis().toInt(), notification)
    }
}
