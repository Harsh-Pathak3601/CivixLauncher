package com.civixshield.launcher

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CivixLlamaClient — Edge Analysis Tier (Unique Feature 7)
 * 
 * Uses OpenRouter to access Llama 3 8B Instruct for lightning-fast, 
 * low-cost scam classification of call transcripts and notifications.
 */
object CivixLlamaClient {
    private val OPENROUTER_API_KEY: String get() = BuildConfig.OPENROUTER_API_KEY
    private val client = OkHttpClient()
    private val gson = Gson()

    suspend fun analyzeThreat(text: String): ThreatAnalysis = withContext(Dispatchers.IO) {
        val prompt = """
            Analyze this call transcript for scams in an Indian context. 
            Text: "$text"
            Respond ONLY in JSON format:
            {
              "score": <0-100>,
              "label": "SCAM" or "SAFE",
              "reasons": "brief explanation"
            }
        """.trimIndent()

        val json = mapOf(
            "model" to "meta-llama/llama-3-8b-instruct:free", 
            "messages" to listOf(
                mapOf("role" to "user", "content" to prompt)
            )
        )

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val requestBody = gson.toJson(json).toRequestBody(mediaType)

        val request = Request.Builder()
            .url("https://openrouter.ai/api/v1/chat/completions")
            .header("Authorization", "Bearer $OPENROUTER_API_KEY")
            .header("HTTP-Referer", "https://civixshield.vercel.app") 
            .post(requestBody)
            .build()

        try {
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: return@withContext ThreatAnalysis(0, "SAFE", "Error: No response body")
            
            val apiResponse = gson.fromJson(body, OpenRouterResponse::class.java)
            val rawContent = apiResponse.choices.firstOrNull()?.message?.content ?: ""
            
            // ── Robust JSON Extraction ──
            // LLMs sometimes wrap JSON in markdown or add conversational filler.
            // This logic extracts the first valid JSON object block.
            val jsonRegex = "\\{.*\\}".toRegex(RegexOption.DOT_MATCHES_ALL)
            val match = jsonRegex.find(rawContent)
            
            if (match != null) {
                val cleanJson = match.value.trim()
                gson.fromJson(cleanJson, ThreatAnalysis::class.java)
            } else {
                android.util.Log.e("CivixLauncher", "AI Response missing JSON: $rawContent")
                ThreatAnalysis(0, "SAFE", "Unclear analysis format")
            }
        } catch (e: Exception) {
            android.util.Log.e("CivixLauncher", "AI Analysis failed: ${e.message}")
            ThreatAnalysis(0, "ERROR", e.message ?: "Unknown error")
        }
    }

    data class ThreatAnalysis(val score: Int, val label: String, val reasons: String)

    private data class OpenRouterResponse(val choices: List<Choice>)
    private data class Choice(val message: Message)
    private data class Message(val content: String)
}
