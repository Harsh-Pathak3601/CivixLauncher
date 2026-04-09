package com.civixshield.launcher

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ── The apps whose notifications we want to monitor ──────────────────────────
private val MONITORED_APPS = setOf(
    "com.google.android.apps.messaging",    // Google Messages (SMS)
    "com.samsung.android.messaging",        // Samsung Messages
    "com.android.mms",                      // Generic/AOSP Messages
    "com.google.android.talk",              // Google Hangouts/Chat
    "com.whatsapp",                         // WhatsApp
    "com.whatsapp.w4b",                     // WhatsApp Business
    "org.telegram.messenger",               // Telegram
    "com.facebook.orca",                    // Messenger
    "com.android.email",                    // Default Email
    "com.google.android.gm",                // Gmail
    "com.microsoft.outlook",               // Outlook
    "com.paytm.business",                  // Paytm Business
    "net.one97.paytm",                     // Paytm
    "in.org.npci.upiapp",                  // BHIM UPI
    "com.phonepe.app",                     // PhonePe
    "com.google.android.apps.nbu.paisa.user", // Google Pay
    "com.civixshield.launcher",            // Self-monitor for testing
)

class CivixNotificationListener : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return

        val packageName = sbn.packageName
        val extras = sbn.notification?.extras ?: return

        // Extract text content from notification
        val title   = extras.getString(Notification.EXTRA_TITLE) ?: ""
        val body    = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: body
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString() ?: ""

        val content = (bigText.ifEmpty { body }).ifEmpty { subText }
        
        // If content is still empty, we can't analyze it
        if (content.isBlank()) return

        // ── Step 1: Run India-specific local pre-screen ──
        val preScore = CivixScamPatterns.preScore("$title $content")

        // ── Smart Filter ──
        val shouldProcess = (packageName in MONITORED_APPS) || (preScore > 0)
        if (!shouldProcess) return

        // ── Step 2: URL Liveness & AI Verification ──
        MainScope().launch {
            var finalScore = preScore
            val urls = extractUrls(content)
            
            for (url in urls) {
                if (!checkUrlLiveness(url)) {
                    android.util.Log.w("CivixLauncher", "🚨 DEAD/SUSPICIOUS LINK: $url")
                    finalScore += 40 
                }
            }

            // ── Step 3: Save to Firestore & Forward ──
            CivixFirestoreVault.saveThreat("SMS", packageName, content, finalScore)
            incrementThreatCounter()
            forwardToCivixShield("SMS", packageName, content)
        }
    }

    private fun extractUrls(text: String): List<String> {
        val urlRegex = "(https?://[^\\s]+)".toRegex()
        return urlRegex.findAll(text).map { it.value }.toList()
    }

    private suspend fun checkUrlLiveness(urlString: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val url = java.net.URL(urlString)
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.requestMethod = "HEAD"
            val responseCode = connection.responseCode
            responseCode in 200..399
        } catch (e: Exception) {
            false 
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // Required override — not needed for threat monitoring
    }

    /**
     * Increments the persistent threat counter stored in SharedPreferences.
     * MainActivity reads this and shows it in the Live Threat Counter widget.
     */
    private fun incrementThreatCounter() {
        val prefs   = applicationContext.getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
        val current = prefs.getInt("threats_blocked", 0)
        prefs.edit().putInt("threats_blocked", current + 1).apply()
    }

    /**
     * Constructs and fires the deep link URI:
     * civix://ingest?sourcetype=SMS&label=com.whatsapp&content=<msg>
     *
     * Strategy:
     *  1. Try startActivity to bring CivixShieldApp to foreground (works when app is open)
     *  2. On failure (app not installed / cold), show a local heads-up notification instead.
     */
    private fun forwardToCivixShield(sourceType: String, label: String, content: String) {
        // Use Uri.Builder.appendQueryParameter() — Android encodes query values exactly once.
        // Manual string concatenation or double-encoding causes Expo Router's
        // decodeURIComponent to crash on malformed '%' sequences.
        val deepLink = android.net.Uri.parse("civix://ingest").buildUpon()
            .appendQueryParameter("sourcetype", sourceType)
            .appendQueryParameter("label", label)
            .appendQueryParameter("content", content)
            .build().toString()

        android.util.Log.d("CivixLauncher", "Forwarding to CivixShield: $deepLink")

        val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(deepLink)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            `package` = "com.civixshield.app"
        }

        var delivered = false
        try {
            applicationContext.startActivity(intent)
            delivered = true
            android.util.Log.d("CivixLauncher", "✅ Deep link delivered to CivixShieldApp")
        } catch (e: Exception) {
            android.util.Log.w("CivixLauncher",
                "⚠️ CivixShield app not responding. Showing local notification. Error: ${e.message}")
        }

        // Fallback: show a local heads-up notification so the user sees the threat
        // even if CivixShieldApp isn't running in the foreground.
        if (!delivered) {
            showFallbackNotification(sourceType, label, content, deepLink)
        }
    }

    /**
     * Shows a local heads-up notification as a fallback when CivixShieldApp
     * is not running. Tapping it opens CivixShieldApp via the deep link.
     */
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
            ).apply {
                description = "Alerts for intercepted scam messages and calls"
                enableVibration(true)
            }
            nm.createNotificationChannel(channel)
        }

        val tapIntent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(deepLink)).apply {
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
        android.util.Log.d("CivixLauncher", "📢 Fallback notification shown for: $sourceType from $label")
    }
}
