package com.civixshield.launcher

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.telephony.TelephonyManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.google.mlkit.nl.entityextraction.*
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File

/**
 * CivixCallMonitorService — Real-time Live Call Analysis (Unique Feature 6)
 * 
 * Strategy: Uses Accessibility Service to intercept "Live Captions" and 
 * integrates Whisper API for more robust transcription/analysis.
 */
class CivixCallMonitorService : AccessibilityService() {

    private var lastAnalyzedText = ""
    private lateinit var entityExtractor: EntityExtractor
    private val serviceScope = CoroutineScope(Dispatchers.Main + Job())
    private val client = OkHttpClient()
    
    private var callStartTime: Long = 0
    private var timerJob: Job? = null
    private var analysisJob: Job? = null
    private val fullCallTranscript = StringBuilder()

    override fun onCreate() {
        super.onCreate()
        val options = EntityExtractorOptions.Builder(EntityExtractorOptions.ENGLISH).build()
        entityExtractor = EntityExtraction.getClient(options)
        entityExtractor.downloadModelIfNeeded()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        
        // Keep the timer/state check for UI feedback - update state BEFORE processing nodes
        checkCallState()

        // ── Critical: Always check for captions regardless of Telephony State ──
        // Sometimes TelephonyManager state is delayed; we want to catch the text immediately.
        val rootNode = rootInActiveWindow ?: event.source
        rootNode?.let { findAndAnalyzeCaptions(it) }
        
        // Check windows (Live Captions are often in a separate 'overlay' window)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            try {
                windows.forEach { window ->
                    window.root?.let { findAndAnalyzeCaptions(it) }
                }
            } catch (e: Exception) {}
        }
    }

    private fun checkCallState() {
        val tm = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val state = tm.callState
        
        if (state == TelephonyManager.CALL_STATE_OFFHOOK) {
            if (callStartTime == 0L) {
                callStartTime = System.currentTimeMillis()
                startTimer()
            }
        } else if (state == TelephonyManager.CALL_STATE_IDLE) {
            if (callStartTime != 0L) {
                stopTimer()
            }
        }
    }

    private fun startTimer() {
        timerJob?.cancel()
        timerJob = serviceScope.launch {
            while (isActive) {
                val elapsed = (System.currentTimeMillis() - callStartTime) / 1000
                updateLiveTimer(elapsed)
                delay(1000)
            }
        }
    }

    private fun stopTimer() {
        timerJob?.cancel()
        timerJob = null
        callStartTime = 0
        fullCallTranscript.clear() // Reset transcript when call ends
        updateLiveTimer(0)
    }

    private fun updateLiveTimer(seconds: Long) {
        val prefs = getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
        prefs.edit().putLong("live_call_duration", seconds).apply()
    }

    private var lastForwardedScore = -1

    private fun findAndAnalyzeCaptions(node: AccessibilityNodeInfo?) {
        node ?: return
        
        // ── REAL CALL CHECK ──
        // Only monitor if a call is actually in progress AND the user enabled it
        if (callStartTime == 0L) return

        val prefs = getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("monitoring_active", false)) return

        // Optimization: Don't dive into non-essential system windows or empty nodes
        if (node.packageName?.contains("google.android.inputmethod") == true) return

        val text = node.text?.toString() ?: node.contentDescription?.toString()
        if (!text.isNullOrBlank()) {
            // Only ingest chunks that seem like actual speech (at least 2 words)
            if (text.length > 8 && text.contains(" ") && !fullCallTranscript.contains(text)) {
                android.util.Log.d("CivixLauncher", "New Transcript Chunk: $text")
                fullCallTranscript.append(" ").append(text)
                
                // Debounce analysis: Wait for natural pause
                startDebouncedAnalysis()
            }
        }

        // Limit depth and breath of search to save CPU
        val childCount = node.childCount
        if (childCount > 50) return // Safety check for malicious/complex layouts

        for (i in 0 until childCount) {
            val child = try { node.getChild(i) } catch (e: Exception) { null }
            child?.let { findAndAnalyzeCaptions(it) }
        }
    }

    private fun startDebouncedAnalysis() {
        analysisJob?.cancel()
        analysisJob = serviceScope.launch {
            delay(3000) // 3s debounce for call transcripts
            val currentContext = fullCallTranscript.toString().trim()
            if (currentContext.isNotEmpty()) {
                processLiveSpeech(currentContext)
            }
        }
    }

    private fun processLiveSpeech(fullText: String) {
        serviceScope.launch {
            val localScore = CivixScamPatterns.preScore(fullText)
            val analysis = CivixLlamaClient.analyzeThreat(fullText)
            
            val finalScore = maxOf(localScore, analysis.score)
            val label = if (finalScore >= 40) "SCAM" else "SAFE"
            val reasons = analysis.reasons

            // Debounce forwarding: Only alert if score jumps by >= 10 points or cross threshold
            if (Math.abs(finalScore - lastForwardedScore) < 10 && finalScore < 80) return@launch
            lastForwardedScore = finalScore

            android.util.Log.w("CivixLauncher", "LIVE VERDICT: $label ($finalScore%) - $reasons")

            if (label == "SCAM" && finalScore >= 70) {
                triggerVibrationAlert()
            }
            
            forwardToApp(fullText, finalScore, label, reasons)
        }
    }

    private fun triggerVibrationAlert() {
        val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as android.os.Vibrator
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            vibrator.vibrate(android.os.VibrationEffect.createWaveform(longArrayOf(0, 300, 100, 300), -1))
        } else {
            vibrator.vibrate(300)
        }
    }

    private fun forwardToApp(text: String, score: Int, label: String, reasons: String) {
        // Persist for Launcher Dashboard "Forensic Report"
        val prefs = getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString("last_report_text", text)
            putInt("last_report_score", score)
            putString("last_report_label", label)
            putString("last_report_reasons", reasons)
            putLong("last_report_time", System.currentTimeMillis())
        }.apply()

        val type = if (label == "SAFE") "SAFE_CALL" else "LIVE_CALL"
        val deepLink = android.net.Uri.parse("civix://ingest").buildUpon()
            .appendQueryParameter("sourcetype", type)
            .appendQueryParameter("label", "LiveMonitor")
            .appendQueryParameter("content", text)
            .appendQueryParameter("score", score.toString())
            .appendQueryParameter("reasons", reasons)
            .build()

        val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, deepLink).apply {
            addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            `package` = "com.civixshield.app"
        }

        // ── CRITICAL UX RULE ──
        // Only foreground the app if the threat is CRITICAL (>= 85).
        // Otherwise, show a notification to avoid disrupting the active call.
        if (score >= 85) {
            try { startActivity(intent) } catch (e: Exception) { showNotification(type, text, deepLink) }
        } else {
            showNotification(type, text, deepLink)
        }
    }

    private fun showNotification(type: String, content: String, deepLink: android.net.Uri) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        val channelId = "civix_live"
        
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = android.app.NotificationChannel(channelId, "Civix Live Monitor", android.app.NotificationManager.IMPORTANCE_HIGH)
            nm.createNotificationChannel(channel)
        }

        val pendingIntent = android.app.PendingIntent.getActivity(
            this, 0, android.content.Intent(android.content.Intent.ACTION_VIEW, deepLink).apply { `package` = "com.civixshield.app" },
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )

        val title = if (type == "SAFE_CALL") "✅ Call is Safe" else "⚠️ Suspicious Call Detected"
        val snippet = if (content.length > 60) content.take(60) + "..." else content

        val notification = androidx.core.app.NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(snippet)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify(1001, notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopTimer()
        serviceScope.cancel()
    }

    override fun onInterrupt() {}
}
