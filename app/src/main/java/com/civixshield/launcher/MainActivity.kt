package com.civixshield.launcher

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat

// ─── CivixShield Color Tokens (matches the web app) ─────────────────────────
val CivixCyan   = Color(0xFF00E5FF)
val CivixYellow = Color(0xFFFFFF00)
val CivixRed    = Color(0xFFDC2626)
val CivixGreen  = Color(0xFF4CAF50)
val CivixDark   = Color(0xFF0A0F14)
val CivixDarker = Color(0xFF050505)

class MainActivity : ComponentActivity() {

    private lateinit var clipboardMonitor: CivixClipboardMonitor

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Create notification channel for CivixShield alerts
        createAlertChannel()

        // Start clipboard link monitor (Unique Feature 5)
        clipboardMonitor = CivixClipboardMonitor(this)
        clipboardMonitor.startMonitoring()

        // Load persisted threat counters (Unique Feature 2)
        val prefs = getSharedPreferences("civix_stats", Context.MODE_PRIVATE)

        handleIntent(intent)

        setContent {
            CivixLauncherTheme {
                // Live reactive counters
                val threatsBlocked = remember { mutableStateOf(prefs.getInt("threats_blocked", 0)) }
                
                // Forensic Report Data
                val lastText = remember { mutableStateOf(prefs.getString("last_report_text", "")) }
                val lastScore = remember { mutableStateOf(prefs.getInt("last_report_score", 0)) }
                val lastLabel = remember { mutableStateOf(prefs.getString("last_report_label", "N/A")) }
                val lastReasons = remember { mutableStateOf(prefs.getString("last_report_reasons", "")) }

                // Poll for updates (simplified for this demo)
                LaunchedEffect(Unit) {
                    while(true) {
                        threatsBlocked.value = prefs.getInt("threats_blocked", 0)
                        
                        lastText.value = prefs.getString("last_report_text", "")
                        lastScore.value = prefs.getInt("last_report_score", 0)
                        lastLabel.value = prefs.getString("last_report_label", "N/A")
                        lastReasons.value = prefs.getString("last_report_reasons", "")
                        
                        kotlinx.coroutines.delay(1000)
                    }
                }

                LauncherDashboard(
                    threatsBlocked    = threatsBlocked.value,
                    lastText          = lastText.value ?: "",
                    lastScore         = lastScore.value,
                    lastLabel         = lastLabel.value ?: "N/A",
                    lastReasons       = lastReasons.value ?: "",
                    onOpenCivixApp    = { openCivixShieldApp() },
                    onRequestNotif    = { requestNotificationAccess() },
                    onFireTestAlert   = { fireTestNotification() }
                )
            }
        }
    }

    // ── Opens the CivixShield React Native / PWA app ──────────────────────────
    private fun openCivixShieldApp() {
        val intent = packageManager.getLaunchIntentForPackage("com.civixshield.app")
        if (intent != null) {
            startActivity(intent)
        } else {
            // Fallback: open Vercel web app in browser
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://civixshield.vercel.app")))
        }
    }

    private fun requestNotificationAccess() {
        startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
    }



    // ── Fires a test scam notification to verify the pipeline works ───────────
    private fun fireTestNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notification = NotificationCompat.Builder(this, "civix_alerts")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("SBI Security Alert")
            .setContentText("Your account is under review. Verify immediately: http://sbi-secure-verify.xyz/login — arrest warrant issued by CBI Cyber Cell.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        nm.notify(1001, notification)
    }

    private fun createAlertChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "civix_alerts",
                "CivixShield Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data
        if (uri?.scheme == "civix" && uri.host == "ingest") {
            val command = uri.getQueryParameter("command")
            if (command == "start_monitoring") {
                getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
                    .edit().putBoolean("monitoring_active", true).apply()
            } else if (command == "stop_monitoring") {
                getSharedPreferences("civix_stats", Context.MODE_PRIVATE)
                    .edit().putBoolean("monitoring_active", false).apply()
            }
        }
    }
}

// ─── Home Screen Dashboard ────────────────────────────────────────────────────

@Composable
fun LauncherDashboard(
    threatsBlocked: Int,
    lastText: String,
    lastScore: Int,
    lastLabel: String,
    lastReasons: String,
    onOpenCivixApp: () -> Unit,
    onRequestNotif: () -> Unit,
    onFireTestAlert: () -> Unit
) {
    val scrollState = rememberScrollState()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CivixDarker)
            .verticalScroll(scrollState)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(40.dp))

        // ── Logo & Title ─────────────────────────────────────────────────────
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Image(
                painter = painterResource(id = R.drawable.logo),
                contentDescription = "CivixShield Logo",
                modifier = Modifier.size(80.dp)
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = "CIVIXSHIELD",
                color = CivixCyan,
                fontSize = 28.sp,
                fontWeight = FontWeight.Black,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 4.sp
            )
        }
        
        Spacer(Modifier.height(8.dp))
        Text(
            text = "> Protection Active",
            color = CivixGreen,
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace
        )

        Spacer(Modifier.height(32.dp))

        // ── Live Threat Counter ──────────────────────────────────────────────
        LiveThreatCounter(threats = threatsBlocked)

        Spacer(Modifier.height(48.dp))

        // ── Action Buttons ───────────────────────────────────────────────────
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            CivixButton("OPEN CIVIXSHIELD",        CivixYellow, onClick = onOpenCivixApp)
            CivixButton("GRANT NOTIFICATION ACCESS", CivixCyan,   onClick = onRequestNotif)
            CivixButton("FIRE TEST ALERT",           CivixRed,    onClick = onFireTestAlert)
        }

        if (lastText.isNotEmpty()) {
            Spacer(Modifier.height(32.dp))
            ForensicReport(lastText, lastScore, lastLabel, lastReasons)
        }

        Spacer(Modifier.height(48.dp))
        Text(
            text = "© 2026 CivixShield — Protection Engine v1.0",
            color = Color.Gray,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            textAlign = TextAlign.Center
        )
    }
}

// ─── Live Threat Counter Widget (Unique Feature 2) ───────────────────────────

@Composable
fun LiveThreatCounter(threats: Int) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CivixRed)
            .background(Color(0xFF1A0000))
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            CounterColumn("MESSAGES\nSCREENED", threats, CivixRed)
        }
    }
}

@Composable
fun CounterColumn(label: String, count: Int, color: Color) {
    val animatedCount by animateIntAsState(
        targetValue = count,
        animationSpec = tween(durationMillis = 800),
        label = "counter"
    )
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = animatedCount.toString(),
            color = color,
            fontSize = 36.sp,
            fontWeight = FontWeight.Black,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = label,
            color = Color.Gray,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            textAlign = TextAlign.Center
        )
    }
}

// ─── Reusable Components ─────────────────────────────────────────────────────

@Composable
fun ForensicReport(text: String, score: Int, label: String, reasons: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, if(score >= 40) CivixRed else CivixGreen)
            .background(Color(0xFF0F172A))
            .padding(16.dp)
    ) {
        Text(
            text = "LIVE FORENSIC REPORT",
            color = if(score >= 40) CivixRed else CivixGreen,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = "VERDICT: $label ($score%)",
            color = Color.White,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = "REASONS: $reasons",
            color = Color.LightGray,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = "TRANSCRIPT CHUNK:",
            color = Color.Gray,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = "\"$text\"",
            color = Color.Gray,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
        )
    }
}

@Composable
fun StatusRow(label: String, isActive: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = "> $label", color = Color.Gray, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        Text(
            text = if (isActive) "● ACTIVE" else "○ INACTIVE",
            color = if (isActive) CivixGreen else CivixRed,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun CivixButton(label: String, accentColor: Color, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .border(1.dp, accentColor),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Transparent,
            contentColor   = accentColor
        ),
        shape = MaterialTheme.shapes.extraSmall,
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(
            text = label,
            fontFamily   = FontFamily.Monospace,
            fontWeight   = FontWeight.Bold,
            letterSpacing = 1.5.sp,
            fontSize     = 13.sp,
            textAlign    = TextAlign.Center
        )
    }
}

@Composable
fun CivixLauncherTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            background = CivixDarker,
            surface    = CivixDark,
            primary    = CivixCyan,
            onBackground = Color.White
        ),
        content = content
    )
}
