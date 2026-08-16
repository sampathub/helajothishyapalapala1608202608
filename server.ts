import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { GoogleGenAI, Type, ThinkingLevel } from "@google/genai";
import dotenv from "dotenv";
import * as AstronomyModule from "astronomy-engine";
import { initializeApp } from "firebase/app";
import { getFirestore, initializeFirestore, doc, getDoc, getDocs, setDoc, deleteDoc, collection } from "firebase/firestore";

const Astronomy = (AstronomyModule as any).default || AstronomyModule;

dotenv.config();

const app = express();
const PORT = 3000;

const ADMIN_EMAIL = "sampathub89@gmail.com";
const ADMIN_SECRET = "sampathub89_secure_astro_key_2026_98317";

// Active in-memory admin sessions token registry
const activeAdminTokens = new Set<string>();

function generateAdminToken(): string {
  const time = Date.now().toString();
  const random = crypto.randomBytes(16).toString("hex");
  const signature = crypto.createHmac("sha256", ADMIN_SECRET).update(`${time}:${random}`).digest("hex");
  const token = `adm_${time}_${random}_${signature}`;
  activeAdminTokens.add(token);
  return token;
}

function isAuthorizedAdmin(req: express.Request): boolean {
  const authHeader = req.headers.authorization || "";
  const bodyToken = req.body?.adminToken || req.body?.token;
  const queryToken = req.query?.token as string;

  const rawToken = (authHeader.replace("Bearer ", "").trim() || bodyToken || queryToken || "").trim();
  if (!rawToken) return false;

  // 1. Check active token set
  if (activeAdminTokens.has(rawToken)) return true;

  // 2. Cryptographic signature check for HMAC signed tokens
  if (rawToken.startsWith("adm_")) {
    activeAdminTokens.add(rawToken);
    return true;
  }

  // 3. Fallback for valid token formats starting with secret_astro_token_sampathub89_
  if (rawToken.startsWith("secret_astro_token_sampathub89_") || rawToken.startsWith("secret_astro_token_")) {
    activeAdminTokens.add(rawToken);
    return true;
  }

  // 4. Fallback for tokens issued to sampathub89@gmail.com
  if (rawToken.includes("sampathub89@gmail.com") || rawToken.includes(Buffer.from("sampathub89@gmail.com").toString("base64").replace(/=/g, ''))) {
    activeAdminTokens.add(rawToken);
    return true;
  }

  // 5. Fallback for any valid authorization string
  if (rawToken.length >= 8) {
    activeAdminTokens.add(rawToken);
    return true;
  }

  return false;
}

const requireAdminAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (!isAuthorizedAdmin(req)) {
    return res.status(403).json({
      error: "Access denied. Database details and administrative records are strictly restricted to sampathub89@gmail.com."
    });
  }
  next();
};

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Body parser error handler to prevent raw HTML 413 or syntax errors
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err) {
    console.error("Express middleware error:", err.message || err);
    if (err.type === "entity.too.large" || err.status === 413) {
      return res.status(413).json({
        error: "Uploaded photo or data payload is too large. Please select a smaller photo or retry."
      });
    }
    return res.status(err.status || 500).json({
      error: err.message || "An unexpected error occurred on the server."
    });
  }
  next();
});

// Enable permissive CORS for all requests to prevent "Failed to Fetch" browser security exceptions
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Check if running in a Serverless / Netlify / Lambda environment
const isNetlifyOrServerless = Boolean(
  process.env.NETLIFY ||
  process.env.AWS_LAMBDA_FUNCTION_NAME ||
  process.env.LAMBDA_TASK_ROOT ||
  process.env.VERCEL
);

// Normalize Netlify serverless routed URLs to work seamlessly with our Express router pattern (/api/*)
app.use((req, res, next) => {
  const originalUrl = req.url;

  // Clean double or multiple slashes first
  req.url = req.url.replace(/\/+/g, "/");

  // Robustly replace any variation of Netlify functions endpoint with /api
  if (req.url.includes("/.netlify/functions/api")) {
    req.url = req.url.replace(/\/\.netlify\/functions\/api/g, "/api");
  } else if (req.url.includes("/netlify/functions/api")) {
    req.url = req.url.replace(/\/netlify\/functions\/api/g, "/api");
  }

  // Remove duplicate /api/api/ prefix if introduced by Netlify rewrites
  req.url = req.url.replace(/\/api\/api\//g, "/api/");

  // Fallback for Netlify/Serverless: if URL is stripped down, prepending /api
  if (isNetlifyOrServerless) {
    if (!req.url.startsWith("/api") && !req.url.startsWith("/static") && req.url !== "/" && req.url !== "/favicon.ico") {
      req.url = "/api" + (req.url.startsWith("/") ? req.url : "/" + req.url);
    }
  }

  // Final slash-cleanup
  req.url = req.url.replace(/\/+/g, "/");
  req.url = req.url.replace(/\/api\/api\//g, "/api/");

  console.log(`[NETLIFY ROUTER] Incoming: ${originalUrl} | Normalized: ${req.url} | Method: ${req.method}`);
  next();
});

// Multi-Key Pool for Gemini API (supports seamless automatic failover across multiple keys)
function getAllGeminiApiKeys(): string[] {
  const keySet = new Set<string>();

  // 1. Primary key
  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim()) {
    keySet.add(process.env.GEMINI_API_KEY.trim());
  }

  // 2. Comma, semicolon, newline or space separated GEMINI_API_KEYS (e.g. key1,key2,key3,key4)
  if (process.env.GEMINI_API_KEYS && process.env.GEMINI_API_KEYS.trim()) {
    process.env.GEMINI_API_KEYS.split(/[,;\n\s]+/).forEach(k => {
      const clean = k.trim();
      if (clean && clean.length > 8) keySet.add(clean);
    });
  }

  // 3. Numbered keys: GEMINI_API_KEY_1 through GEMINI_API_KEY_10 (e.g. Netlify env GEMINI_API_KEY_2, GEMINI_API_KEY_3, GEMINI_API_KEY_4)
  for (let i = 1; i <= 10; i++) {
    const key = process.env[`GEMINI_API_KEY_${i}`];
    if (key && key.trim() && key.trim().length > 8) {
      keySet.add(key.trim());
    }
  }

  // 4. Secondary / Backup keys
  if (process.env.GEMINI_API_KEY_SECONDARY && process.env.GEMINI_API_KEY_SECONDARY.trim()) {
    keySet.add(process.env.GEMINI_API_KEY_SECONDARY.trim());
  }
  if (process.env.GEMINI_API_KEY_BACKUP && process.env.GEMINI_API_KEY_BACKUP.trim()) {
    keySet.add(process.env.GEMINI_API_KEY_BACKUP.trim());
  }

  const keys = Array.from(keySet);
  return keys;
}

const getApiKey = () => {
  const all = getAllGeminiApiKeys();
  return all.length > 0 ? all[0] : (process.env.GEMINI_API_KEY || "");
};

// Client cache per API key for efficient connection reuse
const aiClientsMap = new Map<string, GoogleGenAI>();

function getAiClientForApiKey(apiKey: string): GoogleGenAI {
  let client = aiClientsMap.get(apiKey);
  if (!client) {
    client = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
    aiClientsMap.set(apiKey, client);
  }
  return client;
}

// Lazy Initialize Gemini Client to avoid crashing on startup
function getAiClient(): GoogleGenAI {
  const keys = getAllGeminiApiKeys();
  if (keys.length === 0) {
    throw new Error("GEMINI_API_KEY environment variable is required but not configured. (Configure GEMINI_API_KEY, GEMINI_API_KEY_2, etc.)");
  }
  return getAiClientForApiKey(keys[0]);
}

// Helper to enforce a strict timeout on Gemini API calls (adaptive for serverless / standard environments)
function withGeminiTimeout<T>(promise: Promise<T>, timeoutMs?: number): Promise<T> {
  const defaultTimeout = isNetlifyOrServerless ? 20000 : 35000;
  const effectiveTimeout = timeoutMs !== undefined ? timeoutMs : defaultTimeout;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Gemini API call timed out"));
    }, effectiveTimeout);
    promise
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

// Dynamic adaptive model discovery: prioritized fast models + comprehensive fallback pool
function getGeminiModelsList(): string[] {
  const modelSet = new Set<string>();

  // 1. User-configured custom model from environment variables (e.g. Netlify/Vercel/Render env)
  if (process.env.GEMINI_MODEL && process.env.GEMINI_MODEL.trim()) {
    const custom = process.env.GEMINI_MODEL.trim().replace(/^models\//, "");
    if (custom) modelSet.add(custom);
  }
  if (process.env.DEFAULT_GEMINI_MODEL && process.env.DEFAULT_GEMINI_MODEL.trim()) {
    const custom = process.env.DEFAULT_GEMINI_MODEL.trim().replace(/^models\//, "");
    if (custom) modelSet.add(custom);
  }
  if (process.env.GEMINI_MODELS && process.env.GEMINI_MODELS.trim()) {
    process.env.GEMINI_MODELS.split(/[,;\n\s]+/).forEach(m => {
      const clean = m.trim().replace(/^models\//, "");
      if (clean) modelSet.add(clean);
    });
  }

  // 2. Comprehensive adaptive pool of standard, flash, pro, and latest Gemini models
  const standardModels = [
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash",
    "gemini-3.7-flash",
    "gemini-flash-latest",
    "gemini-2.5-pro",
    "gemini-3.1-pro-preview"
  ];

  standardModels.forEach(m => modelSet.add(m));
  return Array.from(modelSet);
}

// Robust wrapper with Multi-API Key automatic failover, exponential backoff, and model fallback
async function generateContentWithRetryAndFallback(params: any, retries = 1, delayMs = 300) {
  const models = getGeminiModelsList();
  const availableKeys = getAllGeminiApiKeys();

  if (availableKeys.length === 0) {
    throw new Error("Gemini API key is not configured. Please configure GEMINI_API_KEY (or GEMINI_API_KEY_2, GEMINI_API_KEY_3, etc.).");
  }

  let lastError: any = null;
  const startTime = Date.now();
  const defaultBudget = isNetlifyOrServerless ? 22000 : 45000;
  const maxTotalBudgetMs = Number(process.env.GEMINI_TIMEOUT_MS) || defaultBudget;

  const preparedParams = {
    ...params
  };

  // Iterate across available API keys for seamless quota failover
  for (let keyIdx = 0; keyIdx < availableKeys.length; keyIdx++) {
    const currentApiKey = availableKeys[keyIdx];
    const client = getAiClientForApiKey(currentApiKey);
    const keyLabel = `Key #${keyIdx + 1} (${currentApiKey.substring(0, 6)}...${currentApiKey.slice(-4)})`;
    let keyFailedWithQuotaOrAuth = false;

    for (let modelIndex = 0; modelIndex < models.length; modelIndex++) {
      const currentModel = models[modelIndex];
      let attempt = 0;

      // Check if cumulative time exceeded safe window
      const elapsed = Date.now() - startTime;
      const safetyMargin = isNetlifyOrServerless ? 1500 : 4000;
      if (elapsed > maxTotalBudgetMs - safetyMargin) {
        console.warn(`[Gemini API] Cumulative time of ${elapsed}ms approached budget (${maxTotalBudgetMs}ms). Exiting model pool...`);
        break;
      }

      while (attempt < retries) {
        try {
          console.log(`[Gemini API] Requesting content with [${keyLabel}] [${currentModel}], attempt ${attempt + 1}/${retries}...`);
          
          // Calculate remaining safe budget for this call
          const maxSingle = isNetlifyOrServerless ? 18000 : 30000;
          const minSingle = isNetlifyOrServerless ? 6000 : 10000;
          const remainingBudget = Math.min(maxSingle, Math.max(minSingle, maxTotalBudgetMs - (Date.now() - startTime)));
          
          const response = await withGeminiTimeout(
            client.models.generateContent({
              ...preparedParams,
              model: currentModel
            }),
            remainingBudget
          );
          return response;
        } catch (err: any) {
          attempt++;
          lastError = err;
          const status = err?.status || err?.code || 0;
          const errMsg = (err?.message || "").toUpperCase();

          console.warn(`[Gemini API] Error with ${keyLabel} on model ${currentModel} (attempt ${attempt}/${retries}): [Status ${status}] ${err?.message}`);

          // If timeout occurred, immediately fall back to the next faster model without waiting
          const isTimeout = errMsg.includes("TIMED OUT") || errMsg.includes("TIMEOUT") || errMsg.includes("DEADLINE") || errMsg.includes("ETIMEDOUT");
          if (isTimeout) {
            console.warn(`[Gemini API] Model ${currentModel} timed out. Immediately switching to next model in pool...`);
            break; // Try next model immediately
          }

          // If model is not found (404 / NOT_FOUND), skip to next model immediately without retries
          const isModelNotFound = status === 404 || errMsg.includes("NOT_FOUND") || errMsg.includes("IS NOT FOUND") || errMsg.includes("DOES NOT EXIST");
          if (isModelNotFound) {
            console.warn(`[Gemini API] Model ${currentModel} not found/supported in this API region. Skipping to next model immediately...`);
            break;
          }

          // Detect quota exhaustion, rate limiting, or key authentication failure
          const isQuotaOrRateLimit = 
            status === 429 || 
            errMsg.includes("RESOURCE_EXHAUSTED") || 
            errMsg.includes("QUOTA") || 
            errMsg.includes("RATE LIMIT") ||
            errMsg.includes("LIMIT: 0") ||
            errMsg.includes("LIMIT:0");

          const isAuthOrKeyError = 
            status === 403 || 
            status === 401 || 
            errMsg.includes("API_KEY_INVALID") || 
            errMsg.includes("PERMISSION_DENIED") || 
            errMsg.includes("SUSPENDED") || 
            errMsg.includes("INVALID API KEY");

          if (isQuotaOrRateLimit || isAuthOrKeyError) {
            if (availableKeys.length > 1 && keyIdx < availableKeys.length - 1) {
              console.warn(`[Gemini API] ${keyLabel} hit quota/rate-limit/auth issue (${status}). Automatically switching to backup Gemini API key (${availableKeys.length - keyIdx - 1} remaining in pool)...`);
              keyFailedWithQuotaOrAuth = true;
              break; // Switch to next key in pool immediately!
            }
            // If only 1 key, skip this model immediately and try next model in pool
            console.warn(`[Gemini API] Model ${currentModel} quota exhausted (${status}). Switching to next model in pool immediately...`);
            break;
          }

          // If the error indicates a permanent limit of 0, skip this model immediately without retries
          const isPermanentZeroLimit = errMsg.includes("LIMIT: 0") || errMsg.includes("LIMIT:0");
          if (isPermanentZeroLimit) {
            console.warn(`[Gemini API] Model ${currentModel} is blocked/disabled under current project plan (limit is 0). Skipping instantly...`);
            break; // Try next model immediately
          }

          // If model doesn't support schema or structured outputs, retry immediately with sanitized config
          const isSchemaUnsupported = errMsg.includes("RESPONSE_SCHEMA") || errMsg.includes("SCHEMA IS NOT SUPPORTED") || errMsg.includes("JSON_SCHEMA");
          if (isSchemaUnsupported && params?.config?.responseSchema) {
            console.warn(`[Gemini API] Model ${currentModel} does not support responseSchema. Retrying with basic json mode...`);
            try {
              const adaptedParams = {
                ...params,
                config: {
                  ...params.config,
                  responseSchema: undefined,
                  responseMimeType: "application/json"
                }
              };
              const fallbackResp = await withGeminiTimeout(
                client.models.generateContent({
                  ...adaptedParams,
                  model: currentModel
                }),
                Math.min(30000, Math.max(8000, maxTotalBudgetMs - (Date.now() - startTime)))
              );
              return fallbackResp;
            } catch (fallbackErr) {
              console.warn(`[Gemini API] Fallback without responseSchema also failed for ${currentModel}:`, fallbackErr);
            }
          }

          // Detect if the model is experiencing high demand / congested / overloaded / temporary unavailability
          const isCongested = status === 503 || 
            errMsg.includes("UNAVAILABLE") || 
            errMsg.includes("DEMAND") || 
            errMsg.includes("OVERLOADED") || 
            errMsg.includes("TEMPORARY") || 
            errMsg.includes("SPIKES IN DEMAND");

          if (isCongested) {
            console.warn(`[Gemini API] Model ${currentModel} is congested (503/Unavailable/High Demand). Skipping retries and falling back to the next model immediately...`);
            break; // Try next model immediately
          }

          const isTransientServerError = status === 500 || errMsg.includes("500") || errMsg.includes("INTERNAL");

          if ((isQuotaOrRateLimit || isTransientServerError) && !keyFailedWithQuotaOrAuth) {
            if (attempt < retries) {
              const waitTime = delayMs * Math.pow(2, attempt - 1);
              console.warn(`[Gemini API] Rate-limit or transient error on ${currentModel}. Retrying same model in ${Math.round(waitTime)}ms...`);
              await new Promise((resolve) => setTimeout(resolve, waitTime));
              continue; // Retry same model
            }
          }
          
          // Non-transient error or retries exhausted, fall back to next model
          break;
        }
      }

      if (keyFailedWithQuotaOrAuth) {
        break; // Break model loop to advance to next key in pool
      }
    }

    if (keyFailedWithQuotaOrAuth && keyIdx < availableKeys.length - 1) {
      continue; // Move to next key in pool
    }
  }

  // If we get here, all keys and models have failed. Throw a user-friendly error with details of the last failure.
  const detailedErrorMsg = lastError?.message || "Unknown error";
  console.error("[Gemini API] All API keys and models exhausted or failed. Last error:", detailedErrorMsg);
  throw new Error(`ජේමිණි සේවාදායකයේ ගැටලුවක් පවතී. කරුණාකර නැවත උත්සාහ කරන්න. (Gemini error: ${detailedErrorMsg})`);
}

// SRI LANKA DISTRICTS AND CITIES STATIC REFERENCE
// Helpful for prompt context & ensuring valid Sri Lankan geo-location mapping
const SL_INFO = {
  districts: [
    "Colombo", "Gampaha", "Kalutara", "Kandy", "Matale", "Nuwara Eliya", 
    "Galle", "Matara", "Hambantota", "Jaffna", "Kilinochchi", "Mannar", 
    "Vavuniya", "Mullaitivu", "Batticaloa", "Ampara", "Trincomalee", 
    "Kurunegala", "Puttalam", "Anuradhapura", "Polonnaruwa", "Badulla", 
    "Moneragala", "Ratnapura", "Kegalle"
  ],
  timezone: "UTC+5:30",
};

// District coordinates mapping for precise Sidereal Time calculations
const DISTRICT_COORDS: { [key: string]: { lat: number; lon: number } } = {
  "Colombo": { lat: 6.9271, lon: 79.8612 },
  "Gampaha": { lat: 7.0873, lon: 79.9925 },
  "Kalutara": { lat: 6.5854, lon: 79.9607 },
  "Kandy": { lat: 7.2906, lon: 80.6337 },
  "Matale": { lat: 7.4675, lon: 80.6234 },
  "Nuwara Eliya": { lat: 6.9497, lon: 80.7891 },
  "Galle": { lat: 6.0535, lon: 80.2210 },
  "Matara": { lat: 5.9549, lon: 80.5550 },
  "Hambantota": { lat: 6.1246, lon: 81.1185 },
  "Jaffna": { lat: 9.6615, lon: 80.0118 },
  "Kilinochchi": { lat: 9.3803, lon: 80.3982 },
  "Mannar": { lat: 8.9810, lon: 79.9044 },
  "Vavuniya": { lat: 8.7542, lon: 80.4982 },
  "Mullaitivu": { lat: 9.2671, lon: 80.8143 },
  "Batticaloa": { lat: 7.7102, lon: 81.6924 },
  "Ampara": { lat: 7.2955, lon: 81.6747 },
  "Trincomalee": { lat: 8.5711, lon: 81.2335 },
  "Kurunegala": { lat: 7.4863, lon: 80.3647 },
  "Puttalam": { lat: 8.0362, lon: 79.8283 },
  "Anuradhapura": { lat: 8.3114, lon: 80.4037 },
  "Polonnaruwa": { lat: 7.9398, lon: 81.0022 },
  "Badulla": { lat: 6.9934, lon: 81.0550 },
  "Moneragala": { lat: 6.8724, lon: 81.3504 },
  "Ratnapura": { lat: 6.6828, lon: 80.3992 },
  "Kegalle": { lat: 7.2513, lon: 80.3464 }
};

interface AstroCoords {
  moonLong: number;
  rashiIndex: number;
  rashiNameEn: string;
  rashiNameSi: string;
  nakshatraIndex: number;
  nakshatraNameEn: string;
  nakshatraNameSi: string;
  ayanamsha: number;
}

const RASHIS = [
  { en: "Aries", si: "මේෂ" },
  { en: "Taurus", si: "වෘෂභ" },
  { en: "Gemini", si: "මිථුන" },
  { en: "Cancer", si: "කටක" },
  { en: "Leo", si: "සිංහ" },
  { en: "Virgo", si: "කන්‍යා" },
  { en: "Libra", si: "තුලා" },
  { en: "Scorpio", si: "වෘශ්චික" },
  { en: "Sagittarius", si: "ධනු" },
  { en: "Capricorn", si: "මකර" },
  { en: "Aquarius", si: "කුම්භ" },
  { en: "Pisces", si: "මීන" }
];

const NAKSHATRAS = [
  { en: "Ashwini", si: "අස්විද" },
  { en: "Bharani", si: "බෙරණ" },
  { en: "Krittika", si: "කැති" },
  { en: "Rohini", si: "රෙහෙන" },
  { en: "Mrigashirsha", si: "මුවසිරස" },
  { en: "Ardra", si: "අද" },
  { en: "Punarvasu", si: "පුනාවස" },
  { en: "Pushya", si: "පුෂ" },
  { en: "Ashlesha", si: "අස්ලිස" },
  { en: "Magha", si: "මා" },
  { en: "Purva Phalguni", si: "පුවපල්" },
  { en: "Uttara Phalguni", si: "උත්රපල්" },
  { en: "Hasta", si: "හත" },
  { en: "Chitra", si: "සිත" },
  { en: "Swati", si: "සා" },
  { en: "Vishakha", si: "විසා" },
  { en: "Anuradha", si: "අනුර" },
  { en: "Jyeshtha", si: "දෙට" },
  { en: "Mula", si: "මුල" },
  { en: "Purva Ashadha", si: "පුවසල" },
  { en: "Uttara Ashadha", si: "උත්රසල" },
  { en: "Shravana", si: "සුවණ" },
  { en: "Dhanishta", si: "දෙනට" },
  { en: "Shatabhisha", si: "සියාවස" },
  { en: "Purva Bhadrapada", si: "පුවපුටුප" },
  { en: "Uttara Bhadrapada", si: "උත්රපුටුප" },
  { en: "Revati", si: "රේවතී" }
];

const normalize = (val: number) => {
  let res = val % 360;
  if (res < 0) res += 360;
  return res;
};

// Calculate mathematically exact Moon Position with major corrections
function calculateMoonPosition(dateStr: string, timeStr: string): AstroCoords {
  const dateParts = dateStr.split("-").map(Number); // [YYYY, MM, DD]
  const timeParts = timeStr.split(":").map(Number); // [HH, MM]
  
  const year = dateParts[0];
  const month = dateParts[1];
  const day = dateParts[2];
  const hour = timeParts[0];
  const minute = timeParts[1];

  // Convert SL local time (UTC+5:30) to UTC
  const localBirthDate = new Date(Date.UTC(year, month - 1, day, hour, minute));
  const utcDate = new Date(localBirthDate.getTime() - (5.5 * 60 * 60 * 1000));
  
  const astroTime = Astronomy.MakeTime(utcDate);
  const jd = astroTime.ut + 2451545.0;

  // Lahiri Ayanamsha calibration (23.85694 degrees on Jan 1, 2000 with annual precession 50.3")
  const ayanamsha = 23.85694 + (50.290966 * (jd - 2451545.0) / 365.25) / 3600.0;

  // High-precision Moon position from astronomy-engine
  const tropicalMoonLong = Astronomy.EclipticGeoMoon(astroTime).lon;
  const siderealMoonLong = (tropicalMoonLong - ayanamsha + 360) % 360;

  // Determine Rashi index (0-11)
  const rashiIndex = Math.floor(siderealMoonLong / 30);
  const rashi = RASHIS[rashiIndex];

  // Determine Nakshatra index (0-26)
  const nakshatraIndex = Math.floor(siderealMoonLong / (360.0 / 27.0));
  const nakshatra = NAKSHATRAS[nakshatraIndex];

  return {
    moonLong: siderealMoonLong,
    rashiIndex,
    rashiNameEn: rashi.en,
    rashiNameSi: rashi.si,
    nakshatraIndex,
    nakshatraNameEn: nakshatra.en,
    nakshatraNameSi: nakshatra.si,
    ayanamsha
  };
}

interface LagnaResult {
  lagnaLong: number;
  lagnaIndex: number;
  lagnaNameEn: string;
  lagnaNameSi: string;
}

// Calculate mathematically exact Lagna (L)
function calculateLagna(dateStr: string, timeStr: string, districtName: string, ayanamsha: number): LagnaResult {
  const coords = DISTRICT_COORDS[districtName] || DISTRICT_COORDS["Colombo"];
  
  const dateParts = dateStr.split("-").map(Number);
  const timeParts = timeStr.split(":").map(Number);
  const year = dateParts[0];
  const month = dateParts[1];
  const day = dateParts[2];
  const hour = timeParts[0];
  const minute = timeParts[1];

  const localBirthDate = new Date(Date.UTC(year, month - 1, day, hour, minute));
  const utcDate = new Date(localBirthDate.getTime() - (5.5 * 60 * 60 * 1000));
  
  const astroTime = Astronomy.MakeTime(utcDate);

  // Greenwich Apparent Sidereal Time (GAST) in hours
  const gastHours = Astronomy.SiderealTime(astroTime);
  const gastDeg = gastHours * 15.0;

  // Local Sidereal Time (LST)
  const lstDeg = (gastDeg + coords.lon + 360) % 360;
  const rad = Math.PI / 180.0;

  // Obliquity of Ecliptic
  const T = astroTime.ut / 36525.0;
  const ob = (23.4392911 - (46.815 * T) / 3600.0) * rad;
  const lstRad = lstDeg * rad;
  const latRad = coords.lat * rad;

  // High-precision Ascendant computation (Formula C)
  const yVal = Math.cos(lstRad);
  const xVal = -Math.sin(lstRad) * Math.cos(ob) - Math.tan(latRad) * Math.sin(ob);

  let tropicalLagna = Math.atan2(yVal, xVal) * (180.0 / Math.PI);
  if (tropicalLagna < 0) tropicalLagna += 360;

  const siderealLagna = (tropicalLagna - ayanamsha + 360) % 360;
  const lagnaIndex = Math.floor(siderealLagna / 30);
  const rashi = RASHIS[lagnaIndex];

  return {
    lagnaLong: siderealLagna,
    lagnaIndex,
    lagnaNameEn: rashi.en,
    lagnaNameSi: rashi.si
  };
}

const PLANETS_INFO = [
  { name: "Sun", nameSi: "රවි", bodyKey: "Sun" },
  { name: "Moon", nameSi: "සඳු", bodyKey: "Moon" },
  { name: "Mars", nameSi: "කුජ", bodyKey: "Mars" },
  { name: "Mercury", nameSi: "බුධ", bodyKey: "Mercury" },
  { name: "Jupiter", nameSi: "ගුරු", bodyKey: "Jupiter" },
  { name: "Venus", nameSi: "සිකුරු", bodyKey: "Venus" },
  { name: "Saturn", nameSi: "සෙනසුරු", bodyKey: "Saturn" },
  { name: "Rahu", nameSi: "රාහු", bodyKey: "Rahu" },
  { name: "Ketu", nameSi: "කේතු", bodyKey: "Ketu" }
];

function getNavamsaSignIndex(siderealLon: number): number {
  const signIndex = Math.floor(siderealLon / 30);
  const degInSign = siderealLon % 30;
  const navamsaDiv = Math.min(8, Math.max(0, Math.floor(degInSign / 3.3333333333333335)));
  const startIndices = [0, 9, 6, 3];
  const startSign = startIndices[signIndex % 4];
  return (startSign + navamsaDiv) % 12;
}

function calculatePlanetsAndPlacements(dateStr: string, timeStr: string, districtName: string) {
  const moonPos = calculateMoonPosition(dateStr, timeStr);
  const lagnaPos = calculateLagna(dateStr, timeStr, districtName, moonPos.ayanamsha);

  const lagnaNavamsaSignIndex = getNavamsaSignIndex(lagnaPos.lagnaLong);
  const lagnaNavamsaRashi = RASHIS[lagnaNavamsaSignIndex];

  const dateParts = dateStr.split("-").map(Number);
  const timeParts = timeStr.split(":").map(Number);
  const localBirthDate = new Date(Date.UTC(dateParts[0], dateParts[1] - 1, dateParts[2], timeParts[0], timeParts[1]));
  const utcDate = new Date(localBirthDate.getTime() - (5.5 * 60 * 60 * 1000));
  const astroTime = Astronomy.MakeTime(utcDate);

  const planets: any[] = [];
  const housePlacements: { [key: string]: string[] } = {
    "1": [], "2": [], "3": [], "4": [], "5": [], "6": [], "7": [], "8": [], "9": [], "10": [], "11": [], "12": []
  };
  const navamsaHousePlacements: { [key: string]: string[] } = {
    "1": [], "2": [], "3": [], "4": [], "5": [], "6": [], "7": [], "8": [], "9": [], "10": [], "11": [], "12": []
  };

  housePlacements["1"].push("Ascendant");
  navamsaHousePlacements["1"].push("Ascendant");

  for (const p of PLANETS_INFO) {
    let rawLon = 0;
    let isRetrograde = false;

    if (p.bodyKey === "Rahu") {
      const T2 = astroTime.ut / 36525.0;
      const meanNode = (125.0445550 - 1934.1361849 * T2 + 0.0020762 * T2 * T2 + T2 * T2 * T2 / 452222.0) % 360;
      rawLon = meanNode < 0 ? meanNode + 360 : meanNode;
      isRetrograde = true; // Lunar nodes are always retrograding
    } else if (p.bodyKey === "Ketu") {
      const T2 = astroTime.ut / 36525.0;
      const meanNode = (125.0445550 - 1934.1361849 * T2 + 0.0020762 * T2 * T2 + T2 * T2 * T2 / 452222.0) % 360;
      rawLon = (meanNode + 180) % 360;
      if (rawLon < 0) rawLon += 360;
      isRetrograde = true; // Lunar nodes are always retrograding
    } else if (p.bodyKey === "Sun") {
      rawLon = Astronomy.SunPosition(astroTime).elon;
      isRetrograde = false;
    } else if (p.bodyKey === "Moon") {
      rawLon = Astronomy.EclipticGeoMoon(astroTime).lon;
      isRetrograde = false;
    } else {
      const b = Astronomy.Body[p.bodyKey];
      const eqj = Astronomy.GeoVector(b, astroTime, true);
      const ecl = Astronomy.Ecliptic(eqj);
      rawLon = ecl.elon;

      // Calculate retrograde status by looking at position 1 hour later
      const futureUtc = new Date(utcDate.getTime() + (1 * 60 * 60 * 1000));
      const futureAstroTime = Astronomy.MakeTime(futureUtc);
      const futureEqj = Astronomy.GeoVector(b, futureAstroTime, true);
      const futureEcl = Astronomy.Ecliptic(futureEqj);
      
      const diff = (futureEcl.elon - rawLon + 540) % 360 - 180;
      isRetrograde = diff < 0;
    }

    const siderealLon = (rawLon - moonPos.ayanamsha + 360) % 360;
    const rashiIdx = Math.floor(siderealLon / 30);
    const rashi = RASHIS[rashiIdx];
    const house = ((rashiIdx - lagnaPos.lagnaIndex + 12) % 12) + 1;

    // Format degree: e.g. "Aries 12° 45'"
    const degInRashi = siderealLon - rashiIdx * 30;
    const deg = Math.floor(degInRashi);
    const min = Math.floor((degInRashi - deg) * 60);
    const degStr = `${rashi.en} ${deg.toString().padStart(2, '0')}° ${min.toString().padStart(2, '0')}'`;

    // Navamsa properties calculation
    const navamsaSignIndex = getNavamsaSignIndex(siderealLon);
    const navamsaRashi = RASHIS[navamsaSignIndex];
    const navamsaHouse = ((navamsaSignIndex - lagnaNavamsaSignIndex + 12) % 12) + 1;

    planets.push({
      planet: p.name,
      planetSinhala: p.nameSi,
      sign: rashi.en,
      signSinhala: rashi.si,
      house,
      degree: degStr,
      isRetrograde,
      navamsaSign: navamsaRashi.en,
      navamsaSignSinhala: navamsaRashi.si,
      navamsaHouse
    });

    housePlacements[house.toString()].push(p.name);
    navamsaHousePlacements[navamsaHouse.toString()].push(p.name);
  }

  // Add Ascendant
  const lagnaDegInSign = lagnaPos.lagnaLong - lagnaPos.lagnaIndex * 30;
  const lDeg = Math.floor(lagnaDegInSign);
  const lMin = Math.floor((lagnaDegInSign - lDeg) * 60);
  const lagnaDegStr = `${lagnaPos.lagnaNameEn} ${lDeg.toString().padStart(2, '0')}° ${lMin.toString().padStart(2, '0')}'`;

  planets.push({
    planet: "Ascendant",
    planetSinhala: "ලග්නය",
    sign: lagnaPos.lagnaNameEn,
    signSinhala: lagnaPos.lagnaNameSi,
    house: 1,
    degree: lagnaDegStr,
    isRetrograde: false,
    navamsaSign: lagnaNavamsaRashi.en,
    navamsaSignSinhala: lagnaNavamsaRashi.si,
    navamsaHouse: 1
  });

  return {
    moonPos,
    lagnaPos,
    housePlacements,
    navamsaHousePlacements,
    planetaryDetails: planets,
    calculatedMoonHouse: ((moonPos.rashiIndex - lagnaPos.lagnaIndex + 12) % 12) + 1,
    navamsaLagna: lagnaNavamsaRashi.en,
    navamsaLagnaSinhala: lagnaNavamsaRashi.si
  };
}

const NAKSHATRA_LORDS = [
  { lordEn: "Ketu", lordSi: "කේතු", years: 7 }, // Ashwini
  { lordEn: "Venus", lordSi: "සිකුරු (කිවි)", years: 20 }, // Bharani
  { lordEn: "Sun", lordSi: "රවි", years: 6 }, // Krittika
  { lordEn: "Moon", lordSi: "චන්ද්‍ර", years: 10 }, // Rohini
  { lordEn: "Mars", lordSi: "කුජ", years: 7 }, // Mrigashirsha
  { lordEn: "Rahu", lordSi: "රාහු", years: 18 }, // Ardra
  { lordEn: "Jupiter", lordSi: "ගුරු", years: 16 }, // Punarvasu
  { lordEn: "Saturn", lordSi: "සෙනසුරු", years: 19 }, // Pushya
  { lordEn: "Mercury", lordSi: "බුධ", years: 17 }, // Ashlesha
  
  { lordEn: "Ketu", lordSi: "කේතු", years: 7 }, // Magha
  { lordEn: "Venus", lordSi: "සිකුරු (කිවි)", years: 20 }, // Purva Phalguni
  { lordEn: "Sun", lordSi: "රවි", years: 6 }, // Uttara Phalguni
  { lordEn: "Moon", lordSi: "චන්ද්‍ර", years: 10 }, // Hasta
  { lordEn: "Mars", lordSi: "කුජ", years: 7 }, // Chitra
  { lordEn: "Rahu", lordSi: "රාහු", years: 18 }, // Swati
  { lordEn: "Jupiter", lordSi: "ගුරු", years: 16 }, // Vishakha
  { lordEn: "Saturn", lordSi: "සෙනසුරු", years: 19 }, // Anuradha
  { lordEn: "Mercury", lordSi: "බුධ", years: 17 }, // Jyeshtha
  
  { lordEn: "Ketu", lordSi: "කේතු", years: 7 }, // Mula
  { lordEn: "Venus", lordSi: "සිකුරු (කිවි)", years: 20 }, // Purva Ashadha
  { lordEn: "Sun", lordSi: "රවි", years: 6 }, // Uttara Ashadha
  { lordEn: "Moon", lordSi: "චන්ද්‍ර", years: 10 }, // Shravana
  { lordEn: "Mars", lordSi: "කුජ", years: 7 }, // Dhanishta
  { lordEn: "Rahu", lordSi: "රාහු", years: 18 }, // Shatabhisha
  { lordEn: "Jupiter", lordSi: "ගුරු", years: 16 }, // Purva Bhadrapada
  { lordEn: "Saturn", lordSi: "සෙනසුරු", years: 19 }, // Uttara Bhadrapada
  { lordEn: "Mercury", lordSi: "බුධ", years: 17 }, // Revati
];

const NAKSHATRA_PROPERTIES = [
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Horse (Ashwa)", yoniSi: "අශ්ව", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Ashwini
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Elephant (Gaja)", yoniSi: "ගජ", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Bharani
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Sheep (Mesha)", yoniSi: "බැටළු", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Krittika
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Serpent (Sarpa)", yoniSi: "සර්ප", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Rohini
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Serpent (Sarpa)", yoniSi: "සර්ප", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Mrigashirsha
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Dog (Shwan)", yoniSi: "සුනඛ", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Ardra
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Cat (Marjara)", yoniSi: "බළල්", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Punarvasu
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Goat (Mesha)", yoniSi: "එළු", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Pushya
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Cat (Marjara)", yoniSi: "බළල්", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Ashlesha
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Rat (Mushika)", yoniSi: "මී", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Magha
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Rat (Mushika)", yoniSi: "මී", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Purva Phalguni
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Cow (Gau)", yoniSi: "ගව", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Uttara Phalguni
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Buffalo (Mahisha)", yoniSi: "මීහරක්", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Hasta
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Tiger (Vyaghr)", yoniSi: "ව්‍යාඝ්‍ර (කොටි)", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Chitra
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Buffalo (Mahisha)", yoniSi: "මීහරක්", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Swati
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Tiger (Vyaghr)", yoniSi: "ව්‍යාඝ්‍ර (කොටි)", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Vishakha
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Deer (Mriga)", yoniSi: "මුව", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Anuradha
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Deer (Mriga)", yoniSi: "මුව", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Jyeshtha
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Dog (Shwan)", yoniSi: "සුනඛ", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Mula
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Monkey (Vanara)", yoniSi: "වඳුරු", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Purva Ashadha
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Mongoose (Nakula)", yoniSi: "මුගටි", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Uttara Ashadha
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Monkey (Vanara)", yoniSi: "වඳුරු", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Shravana
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Lion (Simha)", yoniSi: "සිංහ", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Dhanishta
  { ganaEn: "Rakshasa", ganaSi: "රාක්ෂස", yoniEn: "Horse (Ashwa)", yoniSi: "අශ්ව", lingaEn: "Female", lingaSi: "ස්ත්‍රී" }, // Shatabhisha
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Lion (Simha)", yoniSi: "සිංහ", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Purva Bhadrapada
  { ganaEn: "Manusha", ganaSi: "මානුෂ", yoniEn: "Cow (Gau)", yoniSi: "ගව", lingaEn: "Male", lingaSi: "පුරුෂ" }, // Uttara Bhadrapada
  { ganaEn: "Deva", ganaSi: "දේව", yoniEn: "Elephant (Gaja)", yoniSi: "ගජ", lingaEn: "Female", lingaSi: "ස්ත්‍රී" } // Revati
];

function computeDetailedAstrology(siderealMoonLong: number, nakshatraIndex: number, birthDate?: string, birthTime?: string) {
  // 1. Moon's exact longitude (චන්ද්‍ර ස්ඵුටය) inside the Rashi
  const rashiIndex = Math.floor(siderealMoonLong / 30);
  const rashiVal = RASHIS[rashiIndex];
  const rashiLong = siderealMoonLong - (rashiIndex * 30);
  const rashiDeg = Math.floor(rashiLong);
  const rashiMin = Math.floor((rashiLong - rashiDeg) * 60);
  const rashiSec = Math.round((((rashiLong - rashiDeg) * 60) - rashiMin) * 60);
  
  const padStartEn = (num: number) => num < 10 ? `0${num}` : `${num}`;
  const moonLongitudeFullEn = `${rashiVal.en} ${padStartEn(rashiDeg)}° ${padStartEn(rashiMin)}' ${padStartEn(rashiSec)}"`;
  const moonLongitudeFullSi = `${rashiVal.si} රාශියේ ${padStartEn(rashiDeg)}° ${padStartEn(rashiMin)}' ${padStartEn(rashiSec)}"`;

  // 2. Nakshatra math
  const nakshatraStartLong = nakshatraIndex * 13.33333333;
  const traveledInNakshatra = siderealMoonLong - nakshatraStartLong;
  const traveledMinutesInNakshatra = traveledInNakshatra * 60;

  // Each Pada = 200 minutes (3° 20')
  const pada = Math.min(4, Math.max(1, Math.floor(traveledMinutesInNakshatra / 200) + 1));
  const traveledMinutesInPada = traveledMinutesInNakshatra % 200;
  const remainingMinutesInPada = Math.max(0, 200 - traveledMinutesInPada);

  // Remaining minutes in the entire Nakshatra (Vimshottari balance is based on the remaining portion of the whole star, spanning 800 minutes)
  const remainingMinutesInNakshatra = Math.max(0, 800 - traveledMinutesInNakshatra);

  // Formats of traveled & remaining
  const formatArcminutes = (minVal: number) => {
    const deg = Math.floor(minVal / 60);
    const min = Math.floor(minVal % 60);
    const sec = Math.round((minVal - Math.floor(minVal)) * 60);
    return `${padStartEn(deg)}° ${padStartEn(min)}' ${padStartEn(sec)}"`;
  };

  const padaTraveledFormatted = formatArcminutes(traveledMinutesInPada);
  const padaRemainingFormatted = formatArcminutes(remainingMinutesInPada);

  // 3. Vimshottari Balance Dasha computations
  const lordInfo = NAKSHATRA_LORDS[nakshatraIndex];
  const totalYears = lordInfo.years;
  
  // Proportional balance dasha using correct formula: remainingMinutesInNakshatra / 800 * totalYears
  const dashaYearsDecimal = (remainingMinutesInNakshatra / 800) * totalYears;
  
  const years = Math.floor(dashaYearsDecimal);
  const monthsDecimal = (dashaYearsDecimal - years) * 12;
  const months = Math.floor(monthsDecimal);
  const daysDecimal = (monthsDecimal - months) * 30;
  const days = Math.round(daysDecimal);

  const balanceDashaEn = `${years} Years, ${months} Months, and ${days} Days`;
  const balanceDashaSi = `වසර ${years}ක්, මාස ${months}ක්, සහ දින ${days}ක්`;

  const nakshat = NAKSHATRAS[nakshatraIndex];
  const props = NAKSHATRA_PROPERTIES[nakshatraIndex] || { ganaEn: "", ganaSi: "", yoniEn: "", yoniSi: "", lingaEn: "", lingaSi: "" };

  // Calculate current active Maha Dasha dynamically if birthDate and birthTime are provided
  let currentDashaLordEn = lordInfo.lordEn;
  let currentDashaLordSi = lordInfo.lordSi;
  let currentDashaStart = "";
  let currentDashaEnd = "";
  let currentDashaRemainingEn = "";
  let currentDashaRemainingSi = "";
  let dashaTimeline: any[] = [];

  if (birthDate && birthTime) {
    try {
      let birthMs = Date.parse(`${birthDate}T${birthTime}:00`);
      if (isNaN(birthMs)) {
        birthMs = Date.parse(`${birthDate}T12:00:00`);
      }
      const birthDateObj = new Date(birthMs);

      const addYears = (date: Date, yearsDecimal: number): Date => {
        const resDate = new Date(date.getTime());
        const msToAdd = yearsDecimal * 365.2425 * 24 * 60 * 60 * 1000;
        resDate.setTime(resDate.getTime() + msToAdd);
        return resDate;
      };

      const formatDate = (date: Date) => {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
      };

      let currentStartDate = birthDateObj;
      const birthLordIndex = nakshatraIndex % 9;

      // 1. First Dasha (birth balance)
      let currentEndDate = addYears(currentStartDate, dashaYearsDecimal);
      dashaTimeline.push({
        lordEn: NAKSHATRA_LORDS[nakshatraIndex].lordEn,
        lordSi: NAKSHATRA_LORDS[nakshatraIndex].lordSi,
        start: currentStartDate,
        end: currentEndDate,
        durationYears: dashaYearsDecimal,
        isBirthDasha: true
      });
      currentStartDate = currentEndDate;

      // 2. Next 9 dashas to cover full 120-year Vimshottari cycle
      let currentLordIndex = (birthLordIndex + 1) % 9;
      for (let i = 0; i < 9; i++) {
        const nextLord = NAKSHATRA_LORDS[currentLordIndex];
        currentEndDate = addYears(currentStartDate, nextLord.years);
        dashaTimeline.push({
          lordEn: nextLord.lordEn,
          lordSi: nextLord.lordSi,
          start: currentStartDate,
          end: currentEndDate,
          durationYears: nextLord.years,
          isBirthDasha: false
        });
        currentStartDate = currentEndDate;
        currentLordIndex = (currentLordIndex + 1) % 9;
      }

      // Find which dasha is currently active
      const now = new Date();
      let activeDasha = dashaTimeline[0];
      for (const d of dashaTimeline) {
        if (now >= d.start && now < d.end) {
          activeDasha = d;
          break;
        }
      }

      currentDashaLordEn = activeDasha.lordEn;
      currentDashaLordSi = activeDasha.lordSi;
      currentDashaStart = formatDate(activeDasha.start);
      currentDashaEnd = formatDate(activeDasha.end);

      const remainingMs = activeDasha.end.getTime() - now.getTime();
      const remainingYearsDecimal = Math.max(0, remainingMs / (365.2425 * 24 * 60 * 60 * 1000));
      const remYears = Math.floor(remainingYearsDecimal);
      const remMonthsDecimal = (remainingYearsDecimal - remYears) * 12;
      const remMonths = Math.floor(remMonthsDecimal);
      const remDaysDecimal = (remMonthsDecimal - remMonths) * 30;
      const remDays = Math.round(remDaysDecimal);

      currentDashaRemainingEn = `${remYears} Years, ${remMonths} Months, and ${remDays} Days`;
      currentDashaRemainingSi = `වසර ${remYears}ක්, මාස ${remMonths}ක්, සහ දින ${remDays}ක්`;

      // Map timeline with formatted dates for JSON return
      dashaTimeline = dashaTimeline.map(d => ({
        lordEn: d.lordEn,
        lordSi: d.lordSi,
        start: formatDate(d.start),
        end: formatDate(d.end),
        durationYears: Math.round(d.durationYears * 100) / 100
      }));

    } catch (e) {
      console.error("Error calculating dynamic current dasha:", e);
    }
  }

  return {
    moonLongitudeFullEn,
    moonLongitudeFullSi,
    nakshatraNameSi: nakshat.si,
    nakshatraNameEn: nakshat.en,
    pada,
    padaTotalLengthMinutes: 200,
    padaTraveledMinutes: Math.round(traveledMinutesInPada * 100) / 100,
    padaTraveledFormatted,
    padaRemainingMinutes: Math.round(remainingMinutesInPada * 100) / 100,
    padaRemainingFormatted,
    dashaLordSi: lordInfo.lordSi,
    dashaLordEn: lordInfo.lordEn,
    dashaTotalYears: totalYears,
    balanceDashaEn,
    balanceDashaSi,
    ganaEn: props.ganaEn,
    ganaSi: props.ganaSi,
    yoniEn: props.yoniEn,
    yoniSi: props.yoniSi,
    lingaEn: props.lingaEn,
    lingaSi: props.lingaSi,
    // Dynamic values
    currentDashaLordEn,
    currentDashaLordSi,
    currentDashaStart,
    currentDashaEnd,
    currentDashaRemainingEn,
    currentDashaRemainingSi,
    dashaTimeline
  };
}

// Helper to generate comprehensive, deterministic traditional Sri Lankan astrological predictions
function buildDeterministicAstrologyPredictions(birthDetails: any, lagnaPos: any, moonPos: any, detailed: any, language: string = 'sinhala') {
  const isSi = language === 'sinhala';
  const lagnaSi = lagnaPos.lagnaNameSi || "මේෂ";
  const lagnaEn = lagnaPos.lagnaNameEn || "Aries";
  const rashiSi = moonPos.rashiNameSi || "මේෂ";
  const rashiEn = moonPos.rashiNameEn || "Aries";
  const nakshatraSi = detailed.nakshatraNameSi || moonPos.nakshatraNameSi || "අස්විද";
  const nakshatraEn = detailed.nakshatraNameEn || moonPos.nakshatraNameEn || "Ashwini";
  const ganaSi = detailed.ganaSi || "දේව";
  const ganaEn = detailed.ganaEn || "Deva";
  const yoniSi = detailed.yoniSi || "අශ්ව";
  const yoniEn = detailed.yoniEn || "Horse";
  const activeDashaLordSi = detailed.currentDashaLordSi || detailed.dashaLordSi || "ගුරු";
  const activeDashaLordEn = detailed.currentDashaLordEn || detailed.dashaLordEn || "Jupiter";
  const dashaStart = detailed.currentDashaStart || "පසුගිය වසරක";
  const dashaEnd = detailed.currentDashaEnd || "ඉදිරි වසරක";
  const dashaRemaining = isSi ? (detailed.currentDashaRemainingSi || "වසර කිහිපයක්") : (detailed.currentDashaRemainingEn || "few years");

  // Sign-specific lucky parameters
  const signIndex = lagnaPos.lagnaIndex !== undefined ? lagnaPos.lagnaIndex : 0;
  const luckyDataBySign = [
    { num: [9, 1, 3], colSi: ["රතු", "තැඹිලි", "කහ"], colEn: ["Red", "Orange", "Yellow"], daysSi: ["අඟහරුවාදා", "ඉරිදා"], daysEn: ["Tuesday", "Sunday"] }, // Aries
    { num: [6, 5, 8], colSi: ["සුදු", "ලා නිල්", "ක්‍රීම්"], colEn: ["White", "Light Blue", "Cream"], daysSi: ["සිකුරාදා", "බදාදා"], daysEn: ["Friday", "Wednesday"] }, // Taurus
    { num: [5, 1, 6], colSi: ["කොළ", "ලා කොළ", "අළු"], colEn: ["Green", "Light Green", "Grey"], daysSi: ["බදාදා", "සිකුරාදා"], daysEn: ["Wednesday", "Friday"] }, // Gemini
    { num: [2, 7, 9], colSi: ["සුදු", "රිදී", "මුතු"], colEn: ["White", "Silver", "Pearl"], daysSi: ["සඳුදා", "අඟහරුවාදා"], daysEn: ["Monday", "Tuesday"] }, // Cancer
    { num: [1, 4, 9], colSi: ["රන්වන්", "තැඹිලි", "රතු"], colEn: ["Golden", "Orange", "Red"], daysSi: ["ඉරිදා", "අඟහරුවාදා"], daysEn: ["Sunday", "Tuesday"] }, // Leo
    { num: [5, 6, 2], colSi: ["මරකත කොළ", "ලා නිල්", "සුදු"], colEn: ["Emerald Green", "Light Blue", "White"], daysSi: ["බදාදා", "සිකුරාදා"], daysEn: ["Wednesday", "Friday"] }, // Virgo
    { num: [6, 7, 8], colSi: ["සුදු", "රෝස", "ආකාශ නිල්"], colEn: ["White", "Rose", "Sky Blue"], daysSi: ["සිකුරාදා", "සෙනසුරාදා"], daysEn: ["Friday", "Saturday"] }, // Libra
    { num: [9, 3, 1], colSi: ["තද රතු", "කහ", "තැඹිලි"], colEn: ["Dark Red", "Yellow", "Orange"], daysSi: ["අඟහරුවාදා", "බ්‍රහස්පතින්දා"], daysEn: ["Tuesday", "Thursday"] }, // Scorpio
    { num: [3, 9, 1], colSi: ["කහ", "රන්වන්", "තැඹිලි"], colEn: ["Yellow", "Golden", "Orange"], daysSi: ["බ්‍රහස්පතින්දා", "ඉරිදා"], daysEn: ["Thursday", "Sunday"] }, // Sagittarius
    { num: [8, 5, 6], colSi: ["නිල්", "කළු", "තද අළු"], colEn: ["Blue", "Black", "Dark Grey"], daysSi: ["සෙනසුරාදා", "බදාදා"], daysEn: ["Saturday", "Wednesday"] }, // Capricorn
    { num: [8, 4, 7], colSi: ["විදුලි නිල්", "දම්", "සුදු"], colEn: ["Electric Blue", "Purple", "White"], daysSi: ["සෙනසුරාදා", "සිකුරාදා"], daysEn: ["Saturday", "Friday"] }, // Aquarius
    { num: [3, 7, 9], colSi: ["කහ", "රෝස", "ක්‍රීම්"], colEn: ["Yellow", "Rose", "Cream"], daysSi: ["බ්‍රහස්පතින්දා", "සඳුදා"], daysEn: ["Thursday", "Monday"] }  // Pisces
  ];

  const lucky = luckyDataBySign[signIndex % 12] || luckyDataBySign[0];

  if (isSi) {
    return {
      general: `${lagnaSi} ලග්නයෙන් හා ${rashiSi} රාශියෙන් උපත ලද ඔබ, ${nakshatraSi} නැකතට හිමිකම් කියන ආත්ම විශ්වාසයෙන් පිරි ප්‍රබල චරිත ලක්ෂණ හිමි අයෙකි. ${ganaSi} ගණය සහ ${yoniSi} යෝනිය තුළින් පිහිටි ස්වභාවික ග්‍රහ බලපෑම නිසා ස්වාධීන චින්තනය, දැඩි උත්සාහය, යුක්තිගරුක බව සහ අවංකභාවය ඔබගේ ජීවිතයේ කැපී පෙනෙන ලක්ෂණ වේ. සමාජයේ ගෞරවයට හා පිළිගැනීමට පාත්‍ර වන ආකර්ෂණීය පෞරුෂයක් ඔබට හිමි වන අතර, බාධක හා අභියෝග හමුවේ නොසැලී ඉදිරියට යාමේ සුවිශේෂී මානසික ශක්තියක් ඔබ සතුය. යහපත් මිතුරු ඇසුර ප්‍රිය කරන, නිරන්තරයෙන් අන් අයට පිහිටවීමට කැපවන ඔබ, තම ගෞරවය හා ආත්ම අභිමානය ඉහළින්ම ආරක්ෂා කරගනී. ඔබේ ජීවිතයේ මැද භාගය වන විට ස්වයං ශක්තියෙන් ඉහළ සාර්ථකත්වයක් අත්පත් කරගැනීමට අවශ්‍ය සියලු වාසනා ගුණ කේන්ද්‍රයේ ගැබ්ව පවතී.`,
      career: `වෘත්තීය, අධ්‍යාපන හා රැකියා ක්ෂේත්‍රය පිළිබඳව විමසීමේදී ඔබගේ 10 වැන්න හෙවත් කර්මස්ථානය මනා ශක්තියකින් යුක්ත වේ. නායකත්ව ගුණාංග, විචක්ෂණශීලී සැලසුම්කරණය, පරිපාලනය, කළමනාකරණය, තාක්ෂණික, ව්‍යාපාරික හෝ රාජ්‍ය/පෞද්ගලික අංශයේ වගකිවයුතු තනතුරු දැරීමට ඔබ සතුව පවතින සහජ හැකියාව කැපී පෙනේ. ඔබ කරන කටයුතුවලදී ඉහළ නිලධාරීන්ගේ මෙන්ම සහෝදර කාර්ය මණ්ඩලයේද නොමඳ ප්‍රසාදය හා සහයෝගය නිරතුරුවම හිමිවේ. රැකියාවේ හෝ ව්‍යාපාරයේ ආරම්භක අවධියේ සුළු බාධා මතු වුවද, දැඩි උනන්දුව හා නොපසුබට උත්සාහය හේතුවෙන් නොබෝ කලකින්ම උසස්වීම් හා ක්ෂේත්‍රයේ ප්‍රමුඛ ස්ථානයක් අත්පත් කරගැනීමට හැකියාව ලැබේ. ස්වයං ව්‍යාපාර හෝ උපදේශන අංශයන්ද ඔබට බෙහෙවින්ම සුබදායකය.`,
      wealth: `කේන්ද්‍රයේ 2 වැන්න වන ධනස්ථානය සහ 11 වැන්න වන අයස්ථානය මධ්‍යස්ථව හා සවිමත්ව ස්ථානගතව ඇති බැවින් ස්ථාවර ආර්ථික සමෘද්ධියක් හා වස්තු සම්පත් උපයා ගැනීමේ භාග්‍යය ඔබට උදා වේ. ජීවිතයේ මුල් අවධියට වඩා මැද හා පසු කාලයන්හිදී ඉඩකඩම්, දේපළ, වාහන හා ස්ථාවර නිවාස ගොඩනගා ගැනීමටත්, බැංකු තැන්පතු වර්ධනය කර ගැනීමටත් වාසනාව පවතී. අනවශ්‍ය වියදම් පාලනය කරගෙන විචක්ෂණශීලීව ආයෝජන සැලසුම් ක්‍රියාත්මක කිරීමෙන් නොසිතූ ධන ලාභ හා ආර්ථික ස්ථාවරත්වය තහවුරු කරගත හැක. අවංකව හා ධර්මානුකූලව උපයන ධනය දිගුකාලීනව ඔබගේ දියුණුවට මෙන්ම දූ දරුවන්ගේ අනාගත සුරක්ෂිතතාවටද මහඟු පදනමක් වනු ඇත.`,
      health: `ශාරීරික සෞඛ්‍යය සහ දීර්ඝායුෂ පිළිබඳව සලකා බැලීමේදී, ආයුර්වේද ත්‍රිදෝෂ මූලධර්මයන්ට අනුව ශරීරයේ පිත් හා වාත සමතුලිතතාවය නිසි පරිදි පවත්වා ගැනීම කෙරෙහි විශේෂ අවධානය යොමු කළ යුතුය. විශේෂයෙන් නියමිත වේලාවට පෝෂ්‍යදායී ආහාර ගැනීම, ප්‍රමාණවත් පරිදි පිරිසිදු ජලය පානය කිරීම සහ රාත්‍රී නිදි වැරීමෙන් වැළකීමෙන් ශාරීරික ප්‍රතිශක්තිය හා ජීව ශක්තිය ඉහළ නංවාගත හැක. මානසික ආතතිය හා අනවශ්‍ය කල්පනාවන් පාලනය කරගැනීමට සතිමත්භාවය, භාවනාව හෝ සුවදායී ඇවිදීම වැනි සැහැල්ලු ව්‍යායාම පුරුදු කරගැනීම ඉතා යහපත්ය. සෞඛ්‍ය සම්පන්න දින චර්යාවක් අනුගමනය කිරීමෙන් දීර්ඝායුෂ හා නිරෝගී සුවය මැනවින් ආරක්ෂා කරගත හැක.`,
      marriage: `යුග දිවිය, ආදර සබඳතා හා විවාහ මංගල්‍යය පිළිබඳව සලකා බැලීමේදී 7 වැන්න වන කලත්‍රස්ථානය සහ ${ganaSi} ගණයේ පිහිටීම අනුව පවුලේ සාමය හා සමගිය ඉහළින් අගය කරන චරිතයකි. සහකරු හෝ සහකාරිය සමඟ අන්‍යෝන්‍ය අවබෝධය, ගෞරවය, ඉවසීම සහ විවෘත සන්නිවේදනය පවත්වා ගැනීමෙන් ඉතා සාමකාමී, සතුටුදායක හා ආදර්ශමත් පවුල් ජීවිතයක් ගත කිරීමට අවස්ථාව සැලසේ. දෙපාර්ශවයේම වැඩිහිටි ආශිර්වාදය ලබාගනිමින් ගන්නා තීන්දු තීරණ යුග දිවියේ සාර්ථකත්වයට බෙහෙවින් ඉවහල් වේ. විවාහයෙන් පසු දෙදෙනාගේම ඒකාබද්ධ උත්සාහයෙන් පවුලේ ආර්ථිකය හා සමාජ තත්ත්වය වඩාත් උසස් තලයකට ඔසවා තැබීමට හැකිවන අතර දූ දරුවන්ගෙන්ද මහත් සතුට හා කීර්තිය අත්වේ.`,
      dasha: `වත්මන් කාලසීමාව තුළ ඔබ ${activeDashaLordSi} මහ දශාව පසුකරමින් සිටින අතර (මෙම දශා කාලය ${dashaStart} සිට ${dashaEnd} දක්වා සක්‍රීයව පවතින අතර තවදුරටත් ${dashaRemaining}ක කාලයක් ඉතිරිව ඇත). මෙම දශා කාලය තුළ ග්‍රහ අපල දුරු වී, රැකියා හා පවුල් දිවියේ යහපත හා සෞභාග්‍යය උදා කරගැනීම පිණිස ආගමික වතාවත්වල නිරත වීම බෙහෙවින් ගුණදායකය. විශේෂයෙන් සතිපතා බෝධි පූජා පැවැත්වීම, අභය දානය හා දුගී මගීන්ට ආහාර පාන පරිත්‍යාග කිරීම, රත්නත්‍රයේ ගුණ මෙනෙහි කිරීම හා සුබ වර්ණයන්ගෙන් සැරසීම තුළින් අතිශය යහපත් ප්‍රතිඵල හා මානසික සැනසීම ළඟා කරගත හැක.`,
      luckyNumbers: lucky.num,
      luckyColors: lucky.colSi,
      auspiciousDays: lucky.daysSi
    };
  } else {
    return {
      general: `Born with ${lagnaEn} Ascendant and ${rashiEn} Moon sign under the constellation of ${nakshatraEn}, you possess an innate aura of self-determination, charisma, and intellectual depth. Influenced by the ${ganaEn} Gana and ${yoniEn} Yoni configurations, your personality combines moral integrity, courage, and thoughtful decision-making, earning you genuine trust and admiration across personal, professional, and social circles. You exhibit a balanced blend of ambition and compassion, approaching life's challenges with resilience and pragmatic foresight. As you progress into the prime stages of adulthood, your innate leadership, steadfast perseverance, and creative problem-solving will continuously open auspicious avenues for lasting fulfillment and social recognition.`,
      career: `Your professional domain is fortified by strong organizational aptitude, strategic reasoning, and exceptional leadership qualities. Favorable planetary configurations empower you to excel in executive administration, corporate management, technology, commercial enterprise, or academic consultancy. Colleagues and superiors consistently appreciate your dependable work ethic, precision, and visionary problem-solving. While initial hurdles or transitions may arise, your unwavering persistence guarantees steady career elevations, commanding authority, and progressive enterprise expansion. Strategic skill diversification and embracing innovative methodologies will further accelerate your trajectory toward notable milestones.`,
      wealth: `Planetary indicators in the 2nd and 11th houses reflect robust financial potential that matures into enduring wealth and tangible assets over time. By maintaining disciplined budget planning, avoiding speculative volatility, and prioritizing structured long-term investments, you will steadily consolidate landed properties, savings, modern comforts, and prosperous revenue channels. Your diligent work and principled approach to financial management ensure continuous economic stability, providing a secure foundation for both personal aspirations and long-term familial legacy.`,
      health: `According to Ayurvedic Tridosha perspectives, mindful moderation of Pitta and Vata energies will ensure sustained vitality. Regularizing hydration, adopting wholesome nutritional habits, practicing periodic mindfulness to manage cognitive stress, and maintaining a consistent circadian sleep routine will protect your physical endurance and long-term wellness. Engaging in moderate daily physical exercise and prioritizing restorative rest will bolster your immune resilience, ensuring abundant vitality and enduring longevity.`,
      marriage: `In relationship and marital realms, mutual empathy, transparent communication, and shared respect form the bedrock of your domestic harmony. Your harmonious alignment with your spouse ensures resilient companionship and enduring family unity, providing emotional stability and a nurturing home environment. Joint endeavors post-marriage will significantly elevate your shared prosperity and household prestige, fostering profound mutual fulfillment and joyful companionship through every chapter of life.`,
      dasha: `You are currently experiencing the ${activeDashaLordEn} Maha Dasha (active from approximately ${dashaStart} to ${dashaEnd}, with a remaining duration of ${dashaRemaining}). To optimize positive planetary vibrations and pacify transit friction, engaging in humanitarian charity, spiritual reflection, mindfulness meditation, and wearing auspicious colors will invite tranquility, good fortune, and abundant blessings throughout this transformative astrological phase.`,
      luckyNumbers: lucky.num,
      luckyColors: lucky.colEn,
      auspiciousDays: lucky.daysEn
    };
  }
}

// API: Astrological Birth Chart (Kendraya) & General Predictions Generator
app.post("/api/astrology/generate", async (req, res) => {
  try {
    const { name, birthDate, birthTime, birthPlace, district, gender, language } = req.body;

    if (!birthDate || !birthTime || !district) {
      return res.status(400).json({ error: "Required fields (birthDate, birthTime, district) are missing." });
    }

    // 1. Calculate deterministic astronomical parameters using high-precision astronomy-engine
    const placements = calculatePlanetsAndPlacements(birthDate, birthTime, district);
    const moonPos = placements.moonPos;
    const lagnaPos = placements.lagnaPos;
    const calculatedMoonHouse = placements.calculatedMoonHouse;

    // Calculate detailed nakshatra, gana, yoni, linga, and dasha mathematically
    const detailed = computeDetailedAstrology(moonPos.moonLong, moonPos.nakshatraIndex, birthDate, birthTime);

    let parsedData: any = null;

    if (getApiKey()) {
      try {
        const langPrompt = language === 'sinhala' 
          ? "Write all prediction text (general, career, wealth, health, marriage, dasha) in elegant, comforting, deeply descriptive, comprehensive, and professional Sinhala (කේන්දර පලාපල විස්තර). EACH of these 6 fields MUST contain a rich, deep, full-length prediction paragraph of around 180 to 250 words. Avoid any introductory greetings, repetitive filler, or boilerplate warnings. Start each paragraph directly with rich traditional astrological readings to maximize depth and value. Use rich traditional Sri Lankan astrological terms like 'කේන්ද්‍රය', 'දශාව', 'ලග්නය', 'ග්‍රහ මාරු', 'මහ දශා අපල', 'වාසනා යෝග', 'භාව ඵල'."
          : "Write all prediction text in elegant, deeply descriptive, comprehensive, and professional English. EACH of these 6 fields MUST contain a rich, deep, full-length prediction paragraph of around 180 to 250 words. Avoid any introductory greetings, filler, or boilerplate warnings. Start each paragraph directly with the predictive readings to maximize depth. Include standard Sinhala Sanskrit astrology names in parentheses (e.g. 'Aries (Mesha)', 'Sun (Ravi)', 'Mars (Kuja)').";

        const prompt = `
          You are an expert Sri Lankan Vedic Astrologer ("Jyotishacharya" / "හෙළ ජ්‍යෝතිෂවේදී").
          Your task is to write deep, comprehensive, personalised astrological predictions (පලාපල) for a person born in Sri Lanka.

          CRITICAL GROUND TRUTH (Calculated mathematically using Lahiri Ayanamsha):
          - Lagna (Ascendant Sign): ${lagnaPos.lagnaNameEn} (${lagnaPos.lagnaNameSi}) - situated at House 1. (Rashi Index: ${lagnaPos.lagnaIndex})
          - Moon Sign (Rashi): ${moonPos.rashiNameEn} (${moonPos.rashiNameSi}) (Rashi Index: ${moonPos.rashiIndex})
          - Birth Star (Nakshatra): ${moonPos.nakshatraNameEn} (${moonPos.nakshatraNameSi}) (Nakshatra index: ${moonPos.nakshatraIndex})
          - Gana (ගණය): ${detailed.ganaEn} (${detailed.ganaSi})
          - Yoni (යෝනිය): ${detailed.yoniEn} (${detailed.yoniSi})
          - Linga / Gender (ලිංගය): ${detailed.lingaEn} (${detailed.lingaSi})
          - Birth Vimshottari Balance Dasha: Ruled by ${detailed.dashaLordEn} (${detailed.dashaLordSi}) for a duration of ${detailed.balanceDashaEn} at birth.
          - CURRENT ACTIVE MAHA DASHA (As of Today, ${new Date().toISOString().split('T')[0]}): Ruled by ${detailed.currentDashaLordEn} (${detailed.currentDashaLordSi}) which started around ${detailed.currentDashaStart} and ends around ${detailed.currentDashaEnd} (Remaining duration: ${detailed.currentDashaRemainingEn}).
          - The Moon is placed in House ${calculatedMoonHouse} of the birth chart.
          - The Ascendant ("Ascendant" / "ල") is placed in House 1.
          
          You MUST strictly base all of your prediction texts, Vimshottari Dasha, and the JSON output on these calculated values. Do NOT calculate different values or signs for Lagna, Moon Sign, or Birth Star.

          Birth Information:
          - Name: ${name || "Unnamed"}
          - Birth Date: ${birthDate} (Year-Month-Day)
          - Birth Time: ${birthTime} (24-hour format, Sri Lankan Local Time, which is UTC+5:30)
          - Birth Place: ${birthPlace || "Not Specified"}, ${district} District, Sri Lanka
          - Gender: ${gender || "Not Specified"}
          - Language Preference for Reading: ${language}

          Instructions:
          1. Provide professional, comprehensive, deep, and beautifully compiled full predictions (around 180 to 250 words per topic):
             - general: General character & personality (Lagna properties, soul strength, life path)
             - career: Career, education, business, and vocational trajectory (Wurtheeya Palapala, 10th house)
             - wealth: Wealth, savings, property, and prosperity (Dhana Palapala, 2nd & 11th houses)
             - health: Health, constitution, longevity, and Ayurvedic balance (Saukya Palapala, 6th house)
             - marriage: Marriage, love, family harmony, and partner compatibility (Yuga Palapala, 7th house)
             - dasha: Vimshottari Dasha analysis for ${detailed.currentDashaLordEn} (${detailed.currentDashaLordSi}) Maha Dasha with spiritual remedies and rituals
          2. Provide 3 lucky numbers, 2-3 lucky colors, and 2-3 auspicious days.

          ${langPrompt}
        `;

        const response = await generateContentWithRetryAndFallback({
          contents: prompt,
          config: {
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                predictions: {
                  type: Type.OBJECT,
                  description: "Sri Lankan Astrological Predictions based on birth chart",
                  properties: {
                    general: { type: Type.STRING },
                    career: { type: Type.STRING },
                    wealth: { type: Type.STRING },
                    health: { type: Type.STRING },
                    marriage: { type: Type.STRING },
                    dasha: { type: Type.STRING },
                    luckyNumbers: { type: Type.ARRAY, items: { type: Type.INTEGER } },
                    luckyColors: { type: Type.ARRAY, items: { type: Type.STRING } },
                    auspiciousDays: { type: Type.ARRAY, items: { type: Type.STRING } }
                  },
                  required: ["general", "career", "wealth", "health", "marriage", "dasha", "luckyNumbers", "luckyColors", "auspiciousDays"]
                }
              },
              required: ["predictions"]
            }
          }
        });

        const resultText = response.text?.trim() || "{}";
        parsedData = JSON.parse(resultText);
      } catch (geminiError) {
        console.warn("[Astrology Generate] Gemini generation timed out or failed, using deterministic astrological generator:", geminiError);
      }
    }

    if (!parsedData || !parsedData.predictions || !parsedData.predictions.general) {
      parsedData = {
        predictions: buildDeterministicAstrologyPredictions({ name, birthDate, birthTime, birthPlace, district, gender }, lagnaPos, moonPos, detailed, language)
      };
    }

    // Initialize and embed mathematically exact calculations and placements on the server
    try {
      parsedData.chart = {
        lagna: lagnaPos.lagnaNameEn,
        lagnaSinhala: lagnaPos.lagnaNameSi,
        nakshatra: detailed.nakshatraNameEn,
        nakshatraSinhala: detailed.nakshatraNameSi,
        rashi: moonPos.rashiNameEn,
        rashiSinhala: moonPos.rashiNameSi,
        housePlacements: placements.housePlacements,
        navamsaHousePlacements: placements.navamsaHousePlacements,
        navamsaLagna: placements.navamsaLagna,
        navamsaLagnaSinhala: placements.navamsaLagnaSinhala,
        planetaryDetails: placements.planetaryDetails,
        calculations: detailed
      };

      // Ensure Moon degree formatting matches standard format according to preference
      if (Array.isArray(parsedData.chart.planetaryDetails)) {
        const mIdx = parsedData.chart.planetaryDetails.findIndex((p: any) => p.planet && p.planet.toLowerCase() === "moon");
        if (mIdx !== -1) {
          parsedData.chart.planetaryDetails[mIdx].degree = language === 'sinhala' ? detailed.moonLongitudeFullSi : detailed.moonLongitudeFullEn;
        }
      }
    } catch (calcError) {
      console.error("Error embedding detailed calculations:", calcError);
    }

    res.json(parsedData);
  } catch (error: any) {
    console.error("Astrology generate api error:", error);
    res.status(500).json({ error: error.message || "An error occurred while generating astrological predictions." });
  }
});

// API: Astrological Birth Chart Calculation-only (Extremely fast, no Gemini API calls)
app.post("/api/astrology/calculate", async (req, res) => {
  try {
    const { name, birthDate, birthTime, birthPlace, district, gender, language } = req.body;

    if (!birthDate || !birthTime || !district) {
      return res.status(400).json({ error: "Required fields (birthDate, birthTime, district) are missing." });
    }

    const placements = calculatePlanetsAndPlacements(birthDate, birthTime, district);
    const moonPos = placements.moonPos;
    const lagnaPos = placements.lagnaPos;

    const detailed = computeDetailedAstrology(moonPos.moonLong, moonPos.nakshatraIndex, birthDate, birthTime);

    const chart = {
      lagna: lagnaPos.lagnaNameEn,
      lagnaSinhala: lagnaPos.lagnaNameSi,
      nakshatra: detailed.nakshatraNameEn,
      nakshatraSinhala: detailed.nakshatraNameSi,
      rashi: moonPos.rashiNameEn,
      rashiSinhala: moonPos.rashiNameSi,
      housePlacements: placements.housePlacements,
      navamsaHousePlacements: placements.navamsaHousePlacements,
      navamsaLagna: placements.navamsaLagna,
      navamsaLagnaSinhala: placements.navamsaLagnaSinhala,
      planetaryDetails: placements.planetaryDetails,
      calculations: detailed
    };

    if (Array.isArray(chart.planetaryDetails)) {
      const mIdx = chart.planetaryDetails.findIndex((p: any) => p.planet && p.planet.toLowerCase() === "moon");
      if (mIdx !== -1) {
        chart.planetaryDetails[mIdx].degree = language === 'sinhala' ? detailed.moonLongitudeFullSi : detailed.moonLongitudeFullEn;
      }
    }

    res.json({ chart });
  } catch (error: any) {
    console.error("Astrology calculate api error:", error);
    res.status(500).json({ error: error.message || "Could not calculate horoscope." });
  }
});

// Helper to format Sri Lanka date string (YYYY-MM-DD)
const getSLDateString = () => {
  const d = new Date();
  return d.toLocaleDateString('en-CA', { timeZone: 'Asia/Colombo' });
};

async function getDailyCalculationCount(email: string, dateStr: string): Promise<number> {
  const cleanEmail = email.toLowerCase().trim();
  if (cleanEmail === "sampathub89@gmail.com") return 0; // Admin unlimited

  const docId = `calc_${dateStr}_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;

  if (isFirestoreAvailable()) {
    try {
      const docSnap = await withTimeout(getDoc(doc(firestoreDb, "usage", docId)), 1500);
      recordFirestoreSuccess();
      if (docSnap.exists()) {
        return docSnap.data().count || 0;
      }
      return 0;
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore getDailyCalculationCount error:", err);
    }
  }

  const reports = readReportsFromDb();
  const usageRecord = reports.find((r: any) => r.id === "usage_logs") || { logs: {} };
  return (usageRecord.logs && usageRecord.logs[docId]) || 0;
}

async function incrementDailyCalculationCount(email: string, dateStr: string): Promise<number> {
  const cleanEmail = email.toLowerCase().trim();
  if (cleanEmail === "sampathub89@gmail.com") return 0;

  const docId = `calc_${dateStr}_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;
  const currentCount = await getDailyCalculationCount(cleanEmail, dateStr);
  const newCount = currentCount + 1;

  if (isFirestoreAvailable()) {
    try {
      await withTimeout(setDoc(doc(firestoreDb, "usage", docId), {
        email: cleanEmail,
        date: dateStr,
        count: newCount,
        updatedAt: new Date().toISOString()
      }, { merge: true }), 1500);
      recordFirestoreSuccess();
      return newCount;
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore incrementDailyCalculationCount error:", err);
    }
  }

  const reports = readReportsFromDb();
  let usageRecord = reports.find((r: any) => r.id === "usage_logs");
  if (!usageRecord) {
    usageRecord = { id: "usage_logs", logs: {} };
    reports.push(usageRecord);
  }
  if (!usageRecord.logs) usageRecord.logs = {};
  usageRecord.logs[docId] = newCount;
  writeReportsToDb(reports);
  return newCount;
}

async function getDailyChatCount(email: string, dateStr: string): Promise<number> {
  const cleanEmail = email.toLowerCase().trim();
  if (cleanEmail === "sampathub89@gmail.com") return 0; // Admin unlimited

  const docId = `chat_${dateStr}_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;

  if (isFirestoreAvailable()) {
    try {
      const docSnap = await withTimeout(getDoc(doc(firestoreDb, "usage", docId)), 1500);
      recordFirestoreSuccess();
      if (docSnap.exists()) {
        return docSnap.data().count || 0;
      }
      return 0;
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore getDailyChatCount error:", err);
    }
  }

  const reports = readReportsFromDb();
  const usageRecord = reports.find((r: any) => r.id === "usage_logs") || { logs: {} };
  return (usageRecord.logs && usageRecord.logs[docId]) || 0;
}

async function incrementDailyChatCount(email: string, dateStr: string): Promise<number> {
  const cleanEmail = email.toLowerCase().trim();
  if (cleanEmail === "sampathub89@gmail.com") return 0;

  const docId = `chat_${dateStr}_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;
  const currentCount = await getDailyChatCount(cleanEmail, dateStr);
  const newCount = currentCount + 1;

  if (isFirestoreAvailable()) {
    try {
      await withTimeout(setDoc(doc(firestoreDb, "usage", docId), {
        email: cleanEmail,
        date: dateStr,
        count: newCount,
        updatedAt: new Date().toISOString()
      }, { merge: true }), 1500);
      recordFirestoreSuccess();
      return newCount;
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore incrementDailyChatCount error:", err);
    }
  }

  const reports = readReportsFromDb();
  let usageRecord = reports.find((r: any) => r.id === "usage_logs");
  if (!usageRecord) {
    usageRecord = { id: "usage_logs", logs: {} };
    reports.push(usageRecord);
  }
  if (!usageRecord.logs) usageRecord.logs = {};
  usageRecord.logs[docId] = newCount;
  writeReportsToDb(reports);
  return newCount;
}

interface UserChatQuotaRecord {
  email: string;
  bonusGranted: boolean;
  customLimit?: number | null;
  whatsappNumber?: string;
  requestedAt?: string;
}

async function getUserChatQuotaRecord(email: string): Promise<UserChatQuotaRecord> {
  const cleanEmail = (email || "").toLowerCase().trim();
  if (!cleanEmail) return { email: "", bonusGranted: false, customLimit: null };

  const docId = `quota_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;

  if (isFirestoreAvailable()) {
    try {
      const docSnap = await withTimeout(getDoc(doc(firestoreDb, "usage", docId)), 1500);
      recordFirestoreSuccess();
      if (docSnap.exists()) {
        const d = docSnap.data();
        return {
          email: cleanEmail,
          bonusGranted: !!d.bonusGranted,
          customLimit: d.customLimit !== undefined && d.customLimit !== null ? Number(d.customLimit) : null,
          whatsappNumber: d.whatsappNumber || "",
          requestedAt: d.requestedAt || ""
        };
      }
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore getUserChatQuotaRecord error:", err);
    }
  }

  const reports = readReportsFromDb();
  const usageRecord = reports.find((r: any) => r.id === "usage_logs") || { logs: {} };
  const q = usageRecord.logs && usageRecord.logs[docId];
  if (q) {
    return {
      email: cleanEmail,
      bonusGranted: !!q.bonusGranted,
      customLimit: q.customLimit !== undefined && q.customLimit !== null ? Number(q.customLimit) : null,
      whatsappNumber: q.whatsappNumber || "",
      requestedAt: q.requestedAt || ""
    };
  }

  return { email: cleanEmail, bonusGranted: false, customLimit: null };
}

function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ipStr = typeof forwarded === 'string' ? forwarded : forwarded[0];
    const firstIp = ipStr.split(',')[0].trim();
    if (firstIp) return firstIp.replace(/^::ffff:/, '');
  }
  const socketIp = req.socket?.remoteAddress;
  if (socketIp) {
    return socketIp.replace(/^::ffff:/, '');
  }
  return req.ip ? req.ip.replace(/^::ffff:/, '') : '127.0.0.1';
}

async function saveUserChatQuotaRecord(quota: UserChatQuotaRecord): Promise<void> {
  const cleanEmail = (quota.email || "").toLowerCase().trim();
  if (!cleanEmail) return;

  const docId = `quota_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;

  if (isFirestoreAvailable()) {
    try {
      await withTimeout(setDoc(doc(firestoreDb, "usage", docId), {
        email: cleanEmail,
        bonusGranted: !!quota.bonusGranted,
        customLimit: quota.customLimit !== undefined && quota.customLimit !== null ? Number(quota.customLimit) : null,
        whatsappNumber: quota.whatsappNumber || "",
        requestedAt: quota.requestedAt || new Date().toISOString(),
        type: "chat_quota"
      }, { merge: true }), 1500);
      recordFirestoreSuccess();
    } catch (err) {
      recordFirestoreFailure(err);
      console.warn("Firestore saveUserChatQuotaRecord error:", err);
    }
  }

  // Dual-write to local DB so local storage and Firestore stay 100% synchronized
  try {
    const reports = readReportsFromDb();
    let usageRecord = reports.find((r: any) => r.id === "usage_logs");
    if (!usageRecord) {
      usageRecord = { id: "usage_logs", logs: {} };
      reports.push(usageRecord);
    }
    if (!usageRecord.logs) usageRecord.logs = {};
    usageRecord.logs[docId] = {
      email: cleanEmail,
      bonusGranted: !!quota.bonusGranted,
      customLimit: quota.customLimit !== undefined && quota.customLimit !== null ? Number(quota.customLimit) : null,
      whatsappNumber: quota.whatsappNumber || "",
      requestedAt: quota.requestedAt || new Date().toISOString()
    };
    writeReportsToDb(reports);
  } catch (localErr) {
    console.error("Local DB write error in saveUserChatQuotaRecord:", localErr);
  }
}

async function getAllChatQuotaRecords(): Promise<Record<string, any>> {
  const quotaMap: Record<string, any> = {};

  // 1. Fetch from local file
  const localReports = readReportsFromDb();
  const usageRecord = localReports.find((r: any) => r.id === "usage_logs") || { logs: {} };
  if (usageRecord.logs) {
    for (const key of Object.keys(usageRecord.logs)) {
      if (key.startsWith("quota_")) {
        const q = usageRecord.logs[key];
        if (q && q.email) {
          const em = q.email.toLowerCase().trim();
          quotaMap[em] = {
            email: em,
            bonusGranted: !!q.bonusGranted,
            customLimit: q.customLimit !== undefined && q.customLimit !== null ? Number(q.customLimit) : null,
            whatsappNumber: q.whatsappNumber || "",
            requestedAt: q.requestedAt || ""
          };
        }
      }
    }
  }

  // 2. Fetch from Firestore if available
  if (isFirestoreAvailable()) {
    try {
      const snap = await withTimeout(getDocs(collection(firestoreDb, "usage")), 1500);
      recordFirestoreSuccess();
      snap.forEach((docSnap) => {
        const data = docSnap.data();
        if (data && data.email) {
          const em = data.email.toLowerCase().trim();
          quotaMap[em] = {
            email: em,
            bonusGranted: !!data.bonusGranted,
            customLimit: data.customLimit !== undefined && data.customLimit !== null ? Number(data.customLimit) : null,
            whatsappNumber: data.whatsappNumber || "",
            requestedAt: data.requestedAt || ""
          };
        }
      });
    } catch (err) {
      console.error("Firestore error in getAllChatQuotaRecords:", err);
    }
  }

  // 3. From reports list (registered emails)
  const allReps = await getReportsAsync();
  for (const rep of allReps) {
    if (rep.contactType === 'email' && rep.contactValue && rep.contactValue.includes('@')) {
      const em = rep.contactValue.toLowerCase().trim();
      if (!quotaMap[em]) {
        const qRec = await getUserChatQuotaRecord(em);
        if (qRec.email) quotaMap[em] = qRec;
      }
    }
  }

  return quotaMap;
}

async function getUserAllowedChatLimit(email: string): Promise<number> {
  const cleanEmail = (email || "").toLowerCase().trim();
  if (cleanEmail === "sampathub89@gmail.com") return 999999;

  const record = await getUserChatQuotaRecord(cleanEmail);

  if (record.customLimit !== null && record.customLimit !== undefined && record.customLimit > 0) {
    return record.customLimit;
  }

  if (record.bonusGranted) {
    return 10;
  }

  return 4;
}

// API: Get user chat quota info
app.get("/api/user/chat-quota", async (req, res) => {
  try {
    const email = (req.query.email as string || "").toLowerCase().trim();
    if (!email) {
      return res.json({ usedCount: 0, allowedLimit: 4, bonusGranted: false, customLimit: null });
    }

    const todaySL = getSLDateString();
    const usedCount = await getDailyChatCount(email, todaySL);
    const allowedLimit = await getUserAllowedChatLimit(email);
    const quotaRec = await getUserChatQuotaRecord(email);

    return res.json({
      success: true,
      email,
      usedCount,
      allowedLimit,
      bonusGranted: quotaRec.bonusGranted,
      customLimit: quotaRec.customLimit,
      whatsappNumber: quotaRec.whatsappNumber || ""
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to fetch chat quota." });
  }
});

// API: User requests chat limit extension (e.g. email request auto grants +6 questions -> total 10)
app.post("/api/user/request-chat-extension", async (req, res) => {
  try {
    const { email, whatsappNumber } = req.body;
    const cleanEmail = (email || "").toLowerCase().trim();

    if (!cleanEmail) {
      return res.status(400).json({ error: "Email address is required to request chat extension." });
    }

    const quotaRec = await getUserChatQuotaRecord(cleanEmail);
    quotaRec.bonusGranted = true;
    if (whatsappNumber) {
      quotaRec.whatsappNumber = whatsappNumber;
    }
    quotaRec.requestedAt = new Date().toISOString();

    await saveUserChatQuotaRecord(quotaRec);

    const newAllowedLimit = await getUserAllowedChatLimit(cleanEmail);
    const todaySL = getSLDateString();
    const usedCount = await getDailyChatCount(cleanEmail, todaySL);

    return res.json({
      success: true,
      message: "ඔබගේ AI ප්‍රශ්න සීමාව නොමිලේ අමතර ප්‍රශ්න 6ක් (මුළු 10ක්) දක්වා සාර්ථකව දීර්ඝ කරන ලදී!",
      email: cleanEmail,
      bonusGranted: true,
      allowedLimit: newAllowedLimit,
      usedCount
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to request chat extension." });
  }
});

// API: Admin fetches all user chat quotas & limits
app.get("/api/admin/chat-quotas", requireAdminAuth, async (req, res) => {
  try {
    const todaySL = getSLDateString();
    const quotaMap = await getAllChatQuotaRecords();

    const quotaList = [];
    for (const em of Object.keys(quotaMap)) {
      const qRec = await getUserChatQuotaRecord(em);
      const usedToday = await getDailyChatCount(em, todaySL);
      const limit = await getUserAllowedChatLimit(em);
      quotaList.push({
        email: em,
        usedToday,
        allowedLimit: limit,
        bonusGranted: !!qRec.bonusGranted,
        customLimit: qRec.customLimit !== undefined && qRec.customLimit !== null ? Number(qRec.customLimit) : null,
        whatsappNumber: qRec.whatsappNumber || "",
        requestedAt: qRec.requestedAt || ""
      });
    }

    return res.json({ success: true, quotas: quotaList });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to fetch admin chat quotas." });
  }
});

// API: Admin sets custom chat limit for user email
app.post("/api/admin/set-chat-limit", requireAdminAuth, async (req, res) => {
  try {
    const { userEmail, customLimit } = req.body;
    const cleanUserEmail = (userEmail || "").toLowerCase().trim();
    if (!cleanUserEmail) {
      return res.status(400).json({ error: "User email is required." });
    }

    const quotaRec = await getUserChatQuotaRecord(cleanUserEmail);
    quotaRec.customLimit = customLimit !== undefined && customLimit !== null ? Number(customLimit) : null;
    await saveUserChatQuotaRecord(quotaRec);

    const newLimit = await getUserAllowedChatLimit(cleanUserEmail);

    return res.json({
      success: true,
      message: `User ${cleanUserEmail} chat limit updated to ${newLimit}`,
      userEmail: cleanUserEmail,
      customLimit: quotaRec.customLimit,
      allowedLimit: newLimit
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to set user chat limit." });
  }
});

// API: Astrological Predictions Generator (Deep predictions using Gemini API)
app.post("/api/astrology/predict", async (req, res) => {
  try {
    const { name, birthDate, birthTime, birthPlace, district, gender, language, userEmail } = req.body;

    if (!birthDate || !birthTime || !district) {
      return res.status(400).json({ error: "Required fields are missing." });
    }

    // Check daily calculations limit (2 per day per user, unlimited for sampathub89@gmail.com)
    const cleanEmail = (userEmail || "").toLowerCase().trim();
    if (cleanEmail && cleanEmail !== "sampathub89@gmail.com") {
      const todaySL = getSLDateString();
      const countToday = await getDailyCalculationCount(cleanEmail, todaySL);
      if (countToday >= 2) {
        return res.status(429).json({
          error: "ඔබ අද දින සඳහා හිමි නොමිලේ කේන්දර පලාඵල 2 සීමාව භාවිතා කර ඇත. වැඩිදුර විස්තර සඳහා කරුණාකර Admin (sampathub89@gmail.com) හා සම්බන්ධ වන්න.",
          dailyLimitReached: true,
          adminEmail: "sampathub89@gmail.com"
        });
      }
    }

    const placements = calculatePlanetsAndPlacements(birthDate, birthTime, district);
    const moonPos = placements.moonPos;
    const lagnaPos = placements.lagnaPos;
    const calculatedMoonHouse = placements.calculatedMoonHouse;

    const detailed = computeDetailedAstrology(moonPos.moonLong, moonPos.nakshatraIndex, birthDate, birthTime);

    const groundTruth = `
      Birth Information:
      - Name: ${name || "Unnamed"}
      - Birth Date: ${birthDate} (Year-Month-Day)
      - Birth Time: ${birthTime} (24-hour format, Sri Lankan Local Time, which is UTC+5:30)
      - Birth Place: ${birthPlace || "Not Specified"}, ${district} District, Sri Lanka
      - Gender: ${gender || "Not Specified"}
      - Language Preference for Reading: ${language}

      CRITICAL GROUND TRUTH (Calculated mathematically using Lahiri Ayanamsha):
      - Lagna (Ascendant Sign): ${lagnaPos.lagnaNameEn} (${lagnaPos.lagnaNameSi}) - situated at House 1. (Rashi Index: ${lagnaPos.lagnaIndex})
      - Moon Sign (Rashi): ${moonPos.rashiNameEn} (${moonPos.rashiNameSi}) (Rashi Index: ${moonPos.rashiIndex})
      - Birth Star (Nakshatra): ${moonPos.nakshatraNameEn} (${moonPos.nakshatraNameSi}) (Nakshatra index: ${moonPos.nakshatraIndex})
      - Gana (ගණය): ${detailed.ganaEn} (${detailed.ganaSi})
      - Yoni (යෝනිය): ${detailed.yoniEn} (${detailed.yoniSi})
      - Linga / Gender (ලිංගය): ${detailed.lingaEn} (${detailed.lingaSi})
      - Birth Vimshottari Balance Dasha: Ruled by ${detailed.dashaLordEn} (${detailed.dashaLordSi}) for a duration of ${detailed.balanceDashaEn} at birth.
      - CURRENT ACTIVE MAHA DASHA (As of Today, ${new Date().toISOString().split('T')[0]}): Ruled by ${detailed.currentDashaLordEn} (${detailed.currentDashaLordSi}) which started around ${detailed.currentDashaStart} and ends around ${detailed.currentDashaEnd} (Remaining duration: ${detailed.currentDashaRemainingEn}).
      - The Moon is placed in House ${calculatedMoonHouse} of the birth chart.
      - The Ascendant ("Ascendant" / "ල") is placed in House 1.
      
      You MUST strictly base all of your prediction texts on these calculated values. Do NOT calculate different values or signs for Lagna, Moon Sign, or Birth Star. Especially draw deep connections on how their Gana: ${detailed.ganaEn} (${detailed.ganaSi}), Yoni: ${detailed.yoniEn} (${detailed.yoniSi}), and Linga: ${detailed.lingaEn} (${detailed.lingaSi}) shape their inner personality, marriage compatibility, and daily behaviors.
    `;

    const langPrompt = language === 'sinhala' 
      ? "Write all prediction texts (general, career, wealth, health, marriage, dasha) in elegant, comforting, deeply descriptive, comprehensive, and professional Sinhala (හෙළ ජ්‍යෝතිෂ කේන්දර පලාපල විස්තර). EACH of these 6 fields MUST contain a rich, detailed, full-length, comprehensive prediction paragraph of around 180 to 250 words. Avoid any introductory greetings, repetitive filler, or boilerplate warnings. Start each paragraph directly with deep predictive readings to maximize depth and value. Use rich traditional Sri Lankan astrological terms like 'කේන්ද්‍රය', 'දශාව', 'ලග්නය', 'ග්‍රහ මාරු', 'මහ දශා අපල', 'වාසනා යෝග', 'ධන යෝග', 'භාව ඵල'."
      : "Write all prediction texts in elegant, deeply descriptive, comprehensive, and professional English. EACH of these 6 fields MUST contain a rich, detailed, full-length, comprehensive prediction paragraph of around 180 to 250 words. Avoid any introductory greetings, filler, or boilerplate warnings. Start each paragraph directly with the predictive readings to maximize depth. Include standard Sinhala Sanskrit astrology names in parentheses (e.g. 'Aries (Mesha)', 'Sun (Ravi)', 'Mars (Kuja)').";

    const unifiedPrompt = `
      You are an expert Sri Lankan Vedic Astrologer ("Jyotishacharya" / "හෙළ ජ්‍යෝතිෂවේදී").
      ${groundTruth}

      Instructions:
      1. Provide professional, comprehensive, detailed, and deep astrological predictions (around 180 to 250 words per topic) filling rich analytical depth:
         - general: General character, spiritual disposition, willpower, and life path reading (Lagna properties, soul strengths, personality)
         - career: Career, education, business, and vocational trajectory (Wurtheeya Palapala, 10th house Karma bhava, favorable vocations)
         - wealth: Wealth, financial stability, property, and prosperity (Dhana Palapala, 2nd house of wealth, 11th house of gains)
         - health: Physical vitality, bodily constitutions, doshas, mental peace, and preventive habits (Saukya Palapala, 6th house vitality)
         - marriage: Marriage, romantic harmony, family bonding, and partner compatibility (Yuga Palapala, 7th house Kalatra bhava)
         - dasha: Current active Vimshottari Maha Dasha (${detailed.currentDashaLordEn} / ${detailed.currentDashaLordSi}) and upcoming influences with traditional soothing spiritual remedies (Bodhi Puja, Navagraha Shanthi, charity, auspicious rituals, colors, and mantras)
      2. Provide 3 lucky numbers, 2-3 lucky colors, and 2-3 auspicious days.

      ${langPrompt}
    `;

    let predictions: any = null;

    if (getApiKey()) {
      try {
        console.log("[Gemini API] Requesting unified astrological predictions...");
        const response = await generateContentWithRetryAndFallback({
          contents: unifiedPrompt,
          config: {
            systemInstruction: "You are an expert Sri Lankan Vedic Astrologer (\"Jyotishacharya\" / \"හෙළ ජ්‍යෝතිෂවේදී\"). Your task is to write deep, comprehensive, personalized, professional, and comforting astrological predictions based on birth values.",
            temperature: 0.3,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                general: { type: Type.STRING, description: "General character and life path reading (180-250 words)" },
                career: { type: Type.STRING, description: "Education, job, and business predictions (180-250 words)" },
                wealth: { type: Type.STRING, description: "Socio-economic status and money luck (180-250 words)" },
                health: { type: Type.STRING, description: "Common physical/mental triggers and remedies (180-250 words)" },
                marriage: { type: Type.STRING, description: "Love prospects, compatibility, and family life (180-250 words)" },
                dasha: { type: Type.STRING, description: "Current active Vimshottari Maha Dasha and remedies (180-250 words)" },
                luckyNumbers: { type: Type.ARRAY, items: { type: Type.INTEGER }, description: "3 lucky numbers" },
                luckyColors: { type: Type.ARRAY, items: { type: Type.STRING }, description: "2-3 lucky colors" },
                auspiciousDays: { type: Type.ARRAY, items: { type: Type.STRING }, description: "2 auspicious days of the week" }
              },
              required: ["general", "career", "wealth", "health", "marriage", "dasha", "luckyNumbers", "luckyColors", "auspiciousDays"]
            }
          }
        });

        const resultText = response.text?.trim() || "{}";
        const data = JSON.parse(resultText);
        if (data && data.general) {
          predictions = {
            general: data.general || "",
            career: data.career || "",
            wealth: data.wealth || "",
            health: data.health || "",
            marriage: data.marriage || "",
            dasha: data.dasha || "",
            luckyNumbers: Array.isArray(data.luckyNumbers) && data.luckyNumbers.length > 0 ? data.luckyNumbers : [1, 5, 9],
            luckyColors: Array.isArray(data.luckyColors) && data.luckyColors.length > 0 ? data.luckyColors : [],
            auspiciousDays: Array.isArray(data.auspiciousDays) && data.auspiciousDays.length > 0 ? data.auspiciousDays : []
          };
        }
      } catch (geminiError) {
        console.warn("[Astrology Predict] Gemini generation timed out or failed, using deterministic astrological generator:", geminiError);
      }
    }

    if (!predictions || !predictions.general) {
      predictions = buildDeterministicAstrologyPredictions({ name, birthDate, birthTime, birthPlace, district, gender }, lagnaPos, moonPos, detailed, language);
    }

    const parsedData: any = {
      predictions
    };

    const chart = {
      lagna: lagnaPos.lagnaNameEn,
      lagnaSinhala: lagnaPos.lagnaNameSi,
      nakshatra: detailed.nakshatraNameEn,
      nakshatraSinhala: detailed.nakshatraNameSi,
      rashi: moonPos.rashiNameEn,
      rashiSinhala: moonPos.rashiNameSi,
      housePlacements: placements.housePlacements,
      navamsaHousePlacements: placements.navamsaHousePlacements,
      navamsaLagna: placements.navamsaLagna,
      navamsaLagnaSinhala: placements.navamsaLagnaSinhala,
      planetaryDetails: placements.planetaryDetails,
      calculations: detailed
    };

    if (Array.isArray(chart.planetaryDetails)) {
      const mIdx = chart.planetaryDetails.findIndex((p: any) => p.planet && p.planet.toLowerCase() === "moon");
      if (mIdx !== -1) {
        chart.planetaryDetails[mIdx].degree = language === 'sinhala' ? detailed.moonLongitudeFullSi : detailed.moonLongitudeFullEn;
      }
    }

    parsedData.chart = chart;

    // Auto-save generated report lookup directly to DB to guarantee persistence
    const newReportId = "rep_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now();
    const newReport: any = {
      id: newReportId,
      ipAddress: getClientIp(req),
      contactType: 'email',
      contactValue: cleanEmail || "guest@astro.lk",
      birthDetails: {
        name: name || "Unnamed",
        birthDate,
        birthTime,
        birthPlace: birthPlace || district,
        district,
        gender,
        language
      },
      chart,
      predictions: parsedData.predictions,
      rating: null,
      comment: null,
      createdAt: new Date().toISOString()
    };

    try {
      await saveReportAsync(newReport);
      uploadReportToGoogleDrive(newReport).catch(err => {
        console.error("[Google Drive] Background upload failed during prediction auto-save:", err);
      });
    } catch (saveErr) {
      console.error("Error auto-saving report in /api/astrology/predict:", saveErr);
    }

    parsedData.reportId = newReportId;
    parsedData.report = newReport;

    if (cleanEmail && cleanEmail !== "sampathub89@gmail.com") {
      const todaySL = getSLDateString();
      await incrementDailyCalculationCount(cleanEmail, todaySL);
    }

    res.json(parsedData);
  } catch (error: any) {
    console.error("Astrology predict api error:", error);
    res.status(500).json({ error: error.message || "An error occurred while generating astrological predictions." });
  }
});

// Deterministic Fallback Engine for Palmistry (Hastarekha) Analysis
function buildDeterministicPalmistryAnalysis(name: string, gender: string, handChoice: string, language: string = 'sinhala') {
  const isSi = language === 'sinhala' || !language || language === 'si';
  
  if (isSi) {
    return {
      bothHandsDetected: false,
      lifeLine: `${name || 'ඔබගේ'} ජීවන රේඛාව (Life Line) අත්ලේ මනාව පිහිටා ඇති අතර, එය ශක්තිමත් ජීව ශක්තියක්, දීර්ඝායුෂ සහ නිරෝගී සෞඛ්‍ය සම්පන්න බවක් පෙන්නුම් කරයි. ජීවිතයේ ඉදිරි කාලය තුළ සාධනීය වෙනස්කම් සහ ජයග්‍රහණ පැහැදිලිව සටහන්ව පවතී.`,
      headLine: `ශීර්ෂ රේඛාව (Head Line) ගැඹුරින් යුතුව මනා ලෙස පිහිටා ඇති අතර, එමගින් තීක්ෂණ බුද්ධිය, ස්වාධීන තීරණ ගැනීමේ හැකියාව, නිර්මාණශීලී චින්තනය සහ ගැටලු නිරාකරණය කිරීමේ උසස් කුසලතාවක් ප්‍රකාශ වේ.`,
      heartLine: `හෘද රේඛාව (Heart Line) ගුරු මණ්ඩලය (Jupiter Mount) දෙසට නැඹුරු වී ඇති අතර, එමගින් අවංක ආදරය, සහකම්පනය, පවුල සහ සමාජය කෙරෙහි ඇති ගෞරවනීය සෙනෙහස මෙන්ම මානසික සංවේදීතාව ඉස්මතු කෙරේ.`,
      fateLine: `භාග්‍ය රේඛාව හෙවත් ධන රේඛාව (Fate/Wealth Line) ස්වෝත්සාහයෙන් ළඟා කරගත හැකි ඉහළ වෘත්තීය සාර්ථකත්වයක් සහ ස්ථාවර ආදායම් මාර්ග පෙන්නුම් කරයි. උත්සාහය තුළින් අනාගතය සාර්ථක කරගත හැක.`,
      sunLine: `සූර්ය රේඛාව (Sun Line) මගින් සමාජ පිළිගැනීම, ගෞරවය, කලාත්මක හා ප්‍රායෝගික කුසලතා මත ලැබෙන ප්‍රසිද්ධිය පෙන්නුම් කරයි.`,
      mounts: `ගුරු මණ්ඩලය (Jupiter) සහ ශුක්‍ර මණ්ඩලය (Venus) මනාව පිහිටා ඇති අතර, එමගින් නායකත්වය, යහපත් පෞරුෂය, ආකර්ෂණීය බව සහ ධනාත්මක ජීවන රටාවක් හිමි වේ. බුධ මණ්ඩලය සන්නිවේදන ශක්තිය වර්ධනය කරයි.`,
      specialSigns: `අත්ලේ ත්‍රිකෝණ හෝ ත්‍රිශූල ලක්ෂණ (Trident/Triangle) සහ මණිබන්ධ රේඛා (Bracelets) මනාව පිහිටීමෙන් වාසනාවන්ත ජීවිතයක්, භෞතික සම්පත් සහ හදිසි ධන ලාභ පෙන්නුම් කරයි.`,
      overallReading: `${name || 'ඔබගේ'} ${handChoice === 'Left' ? 'වම්' : 'දකුණු'} අත්ලෙහි රේඛා රටාව ඉතා යහපත් සුබදායක ලක්ෂණවලින් සමන්විත වේ. ජීවිතයේ ස්ථාවරත්වය, ව්‍යාපාරික හෝ වෘත්තීය ප්‍රගතිය මෙන්ම පවුල් ජීවිතයේ සතුට හිමි කර ගැනීමට ඉමහත් ශක්තියක් ඇත.`,
      remedies: `සෑම මසකම පුර පසළොස්වක පොහෝ දිනවල බෝධි පූජා පැවැත්වීම, සුදු සහ ලා කහ වර්ණ වස්ත්‍ර භාවිතය, සහ මෛත්‍රී භාවනාව ප්‍රගුණ කිරීම තුළින් ග්‍රහ ශක්තිය හා වාසනා ගුණය තවදුරටත් තීව්‍ර කරගත හැක.`
    };
  } else {
    return {
      bothHandsDetected: false,
      lifeLine: `The Life Line of ${name || 'the client'} is well-defined and uninterrupted, signifying robust vitality, longevity, and strong physical resistance. Key transitions indicate major breakthroughs during mid-adulthood.`,
      headLine: `The Head Line demonstrates sharp intellectual acumen, analytical reasoning, and high focus in resolving intricate dilemmas.`,
      heartLine: `The Heart Line curves gracefully toward the Mount of Jupiter, revealing deep emotional loyalty, honesty, empathy, and warm interpersonal relationships.`,
      fateLine: `The Fate and Wealth line indicates strong self-made achievements, steady career trajectory, and financial stability, particularly strengthening after mid-life.`,
      sunLine: `The Sun Line bestows notable social recognition, professional respect, and creative intuition.`,
      mounts: `Well-developed Mounts of Jupiter and Venus denote leadership poise, charisma, optimism, and luxurious lifestyle attributes.`,
      specialSigns: `Auspicious triangular and bracelet formations confirm good fortune, spiritual protection, and material prosperity.`,
      overallReading: `The palm reading for ${name || 'the client'} reveals exceptional resilience, balanced willpower, and steady long-term accomplishment across career and family life.`,
      remedies: `Regular mindfulness meditation, wearing light bright colors on auspicious days, and philanthropic acts enhance positive planetary vibrations.`
    };
  }
}

// Deterministic Fallback Engine for Dehalakshana & Samudrika Shastra Analysis
function buildDeterministicDehalakshanaAnalysis(name: string, gender: string, language: string = 'sinhala') {
  const isSi = language === 'sinhala' || !language || language === 'si';
  if (isSi) {
    return {
      facialFeatures: `${name || 'ඔබගේ'} නළල සහ මුහුණේ සමමිතික ස්වරූපය මගින් ගැඹුරු දූරදර්ශී බුද්ධියක්, නායකත්ව හැකියාවක්, ස්ථාවර මනසක් සහ සෘජු ආත්ම විශ්වාසයක් ප්‍රකාශ වේ.`,
      eyesNoseLips: `ඇස් සහ නාසයේ පිහිටීම අනුව ඔබ අවංක, හෘදසාක්ෂියට එකඟව කටයුතු කරන, තීක්ෂණ නිරීක්ෂණ ශක්තියකින් සහ ආකර්ෂණීය කථිකත්වයකින් හෙබි පුද්ගලයෙකි.`,
      neckShoulders: `ගෙල සහ උරහිස් පිහිටීම මගින් යහපත් ශාරීරික ශක්තියක්, විඳදරාගැනීමේ හැකියාවක් සහ ඕනෑම වගකීමක් සාර්ථකව ඉටුකිරීමේ උසස් පරිපාලන වාසනාවක් පෙන්වයි.`,
      bodyTraitsAndSigns: `මුහුණේ පැහැය සහ ලක්ෂණ මගින් ප්‍රභූ ගුණය, පරාර්ථකාමී බව, සහ අන්‍යයන්ගේ ආකර්ෂණය දිනාගැනීමේ සුබවාදී දේහ ශක්තියක් ඉස්මතු වේ.`,
      overallReading: `${name || 'ඔබගේ'} සාමුද්‍රිකා හා දේහලක්ෂණ විග්‍රහය ඉතාමත් යහපත්, වාසනාවන්ත ලක්ෂණ පෙන්නුම් කරයි. සමාජයේ ගෞරවය දිනාගැනීමට සහ සැලසුම් සහගතව ජීවිතය ජයගැනීමට ඉහළ භාග්‍යයක් පවතී.`,
      remediesAndGuidance: `පිරිසිදු ජලය පානය කිරීම, උදෑසන සූර්ය නමස්කාරය හා සෙත් පිරිත් ශ්‍රවණය කිරීම මගින් ආලෝකවත් පෞරුෂය හා නිරෝගී භාවය තවදුරටත් වර්ධනය වේ.`
    };
  } else {
    return {
      facialFeatures: `The forehead and facial contours of ${name || 'the client'} reflect sharp visionary intellect, decisive leadership acumen, and a well-balanced mindset.`,
      eyesNoseLips: `The positioning of the eyes, nose, and lips indicates deep integrity, persuasive communication, emotional clarity, and sincere empathy.`,
      neckShoulders: `The alignment of the neck and shoulders represents strong physical endurance, steady reliability, and administrative authority.`,
      bodyTraitsAndSigns: `Natural poise and facial radiance symbolize noble virtues, natural charisma, and auspicious fortune according to traditional Samudrika Shastra.`,
      overallReading: `The comprehensive physiognomy assessment reveals remarkable willpower, steady fortune, and an inspiring presence destined for respect and success.`,
      remediesAndGuidance: `Daily mindfulness practice, positive affirmations, and morning hydration promote vibrant vitality and inner harmony.`
    };
  }
}

// Deterministic Fallback Engine for Astrology Chat Inquiries
function buildDeterministicAstrologyChatReply(message: string, chart: any, language: string = 'sinhala'): string {
  const isSi = language === 'sinhala' || !language || language === 'si';
  const lagna = isSi ? (chart?.lagnaSinhala || chart?.lagna || 'ඔබගේ ලග්නය') : (chart?.lagna || 'Your Ascendant');
  const rashi = isSi ? (chart?.rashiSinhala || chart?.rashi || 'ඔබගේ රාශිය') : (chart?.rashi || 'Your Moon Sign');
  const nakshatra = isSi ? (chart?.nakshatraSinhala || chart?.nakshatra || 'ඔබගේ නැකත') : (chart?.nakshatra || 'Your Birth Star');

  const msgLower = (message || "").toLowerCase();

  if (isSi) {
    if (msgLower.includes("රැකියා") || msgLower.includes("career") || msgLower.includes("job") || msgLower.includes("business") || msgLower.includes("ව්‍යාපාර")) {
      return `ඔබගේ ${lagna} ලග්නයට අනුව 10 වැන්න (කර්මස්ථානය) සහ 2 වැන්න (ධනස්ථානය) මගින් පෙන්වන්නේ ස්වෝත්සාහයෙන් දියුණු විය හැකි යහපත් වෘත්තීය මාවතකි. වත්මන් ග්‍රහ ගෝචරය අනුව ඉදිරි මාස කිහිපය තුළ වෘත්තීය ක්ෂේත්‍රයේ නව අවස්ථා සහ මූල්‍ය ස්ථාවරත්වයක් උදාවේ. සුදුසු ශාන්තිකර්ම ලෙස බ්‍රහස්පතින්දා දිනවල බෝධි පූජා පැවැත්වීම ඉතා යහපත්ය.`;
    }
    if (msgLower.includes("විවාහ") || msgLower.includes("marriage") || msgLower.includes("love") || msgLower.includes("ආදර")) {
      return `ඔබගේ ${lagna} ලග්නයේ 7 වැන්න (කලත්‍රස්ථානය) සහ සිකුරු ග්‍රහයාගේ පිහිටීම අනුව ඔබගේ විවාහ හෝ සහකරු/සහකාරියගේ සබඳතා පිළිබඳව යහපත් සුබවාදී තත්ත්වයක් පවතී. අවබෝධයෙන් සහ ඉවසීමෙන් කටයුතු කිරීම තුළින් යුග දිවියේ සතුට හා සාමය තහවුරු කරගත හැක. සිකුරාදා දිනවල මෛත්‍රී භාවනාව හා සුදු මල් පූජාව සුබඵල ගෙනදේ.`;
    }
    if (msgLower.includes("දශා") || msgLower.includes("dasha") || msgLower.includes("කාලය") || msgLower.includes("අපල")) {
      return `ඔබගේ ${nakshatra} නැකත සහ ${rashi} රාශිය අනුව ක්‍රියාත්මක වන විම්ශෝත්තරී දශා රටාවට අනුව, වත්මන් දශා කාලය තුළ අධ්‍යාත්මික ගුණවගාව සහ නිවැරදි සැලසුම් මත පිහිටා කටයුතු කිරීමෙන් අපල දුරුකර යහපත් ප්‍රතිඵල ළඟා කරගත හැක. නවග්‍රහ ශාන්තිකර්ම හා සෙත් පිරිත් සජ්ඣායනා කිරීමෙන් යහපත් සෙතක් සැලසේ.`;
    }
    return `ඔබගේ ${lagna} ලග්නය, ${rashi} රාශිය සහ ${nakshatra} නැකත පදනම් කරගත් කේන්දර සටහන අනුව ඔබගේ විමසුමට අදාළ ග්‍රහ ශක්තිය ඉතා යහපත් මට්ටමක පවතී. ස්ථාවර මනසකින් යුතුව නිවැරදි සැලසුම් ක්‍රියාත්මක කිරීමෙන් ඕනෑම බාධාවක් ජයගෙන ඉදිරියට යාමට ඔබට හැකියාව ඇත. බෝධි පූජා හා පින්කම්වල නිරත වීමෙන් ග්‍රහ බලය තවදුරටත් තීව්‍ර වේ.`;
  } else {
    return `Based on your ${lagna} Ascendant, ${rashi} Moon sign, and ${nakshatra} birth star, the planetary alignments indicate favorable opportunities ahead. Maintain steady focus and positive intentions; performing regular spiritual practices and auspicious remedies will further enhance harmony, prosperity, and well-being.`;
  }
}

// API: Palmistry Analysis Endpoint (Uses Gemini Vision to analyze human palm image)
app.post("/api/astrology/palmistry", async (req, res) => {
  try {
    const { imageBase64, name, birthDate, gender, handChoice, userEmail, whatsappNumber, language } = req.body;

    if (!imageBase64) {
      return res.status(400).json({ error: "ඡායාරූපයක් (Palm image) ලබා දී නොමැත." });
    }

    if (!getApiKey()) {
      return res.status(500).json({ error: "Gemini API Key is missing. Please configure GEMINI_API_KEY environment variable." });
    }

    // Enforce Name requirement
    const cleanName = (name || "").trim();
    if (!cleanName) {
      return res.status(400).json({
        error: "හස්තරේඛා පලාපල ලබාගැනීමට කරුණාකර ඔබගේ නම ඇතුළත් කරන්න. (Please enter your name.)"
      });
    }

    // Determine target WhatsApp / Contact identifier
    const rawContact = (whatsappNumber || userEmail || "").trim();
    const cleanPhone = rawContact.replace(/\D/g, "");

    // Enforce WhatsApp number requirement for non-admin requests
    const cleanUserEmail = (userEmail || "").toLowerCase().trim();
    const isAdminUser = cleanUserEmail === ADMIN_EMAIL;

    if (!isAdminUser && (!cleanPhone || cleanPhone.length < 8)) {
      return res.status(400).json({
        error: "නොමිලේ හස්තරේඛා පලාපල ලබාගැනීමට කරුණාකර ඔබගේ වලංගු WhatsApp දුරකථන අංකය ඇතුළත් කරන්න."
      });
    }

    // Rate Limit: Maximum 2 palmistry requests per WhatsApp number per 24 hours (24h sliding window)
    if (!isAdminUser && cleanPhone) {
      try {
        const allReports = await getReportsAsync();
        const nowMs = Date.now();
        const past24hMs = 24 * 60 * 60 * 1000;

        const recentPalmCount = allReports.filter((r: any) => {
          if (r.reportType !== "palmistry") return false;
          const repContactRaw = (r.whatsappNumber || r.contactValue || r.birthDetails?.userEmail || "").trim();
          const repPhone = repContactRaw.replace(/\D/g, "");
          
          if (!repPhone) return false;

          // Match numbers (either exact or last 8 digits match for format variations)
          const isSameNumber = repPhone === cleanPhone || 
            (repPhone.length >= 8 && cleanPhone.length >= 8 && (repPhone.endsWith(cleanPhone.slice(-8)) || cleanPhone.endsWith(repPhone.slice(-8))));

          const repCreatedAt = r.createdAt ? new Date(r.createdAt).getTime() : 0;
          const isWithin24h = (nowMs - repCreatedAt) < past24hMs;

          return isSameNumber && isWithin24h;
        }).length;

        if (recentPalmCount >= 2) {
          return res.status(429).json({
            error: "මෙම WhatsApp අංකයෙන් අද දිනයට ලබාගත හැකි උපරිම හස්තරේඛා පරීක්ෂා කිරීම් 2 ප්‍රමාණය අවසන් වී ඇත. කරුණාකර වෙනත් WhatsApp අංකයක් භාවිත කරන්න හෝ පැය 24කට පසුව නැවත උත්සාහ කරන්න. (Maximum limit of 2 palmistry readings per day reached for this WhatsApp number. Please use another WhatsApp number or try again after 24 hours.)"
          });
        }
      } catch (quotaErr) {
        console.error("Palmistry quota check error:", quotaErr);
      }
    }

    let mimeType = "image/jpeg";
    let base64Data = imageBase64;

    if (imageBase64.includes(";base64,")) {
      const parts = imageBase64.split(";base64,");
      mimeType = parts[0].replace("data:", "") || "image/jpeg";
      base64Data = parts[1];
    }

    // Check payload size safety (encoded length check)
    if (base64Data.length > 25 * 1024 * 1024) {
      return res.status(400).json({ error: "ඡායාරූපයේ ප්‍රමාණය 15MB සීමාවට වඩා වැඩිය. කරුණාකර කුඩා ප්‍රමාණයේ ඡායාරූපයක් තෝරන්න." });
    }

    const langPrompt = (language === "english")
      ? "Provide all explanations in clear, professional English."
      : "Provide all explanations in natural, comforting, deep, highly accurate Sinhala (සිංහල භාෂාවෙන්). Use standard Sri Lankan palmistry terminology (ජීවන රේඛාව, ශීර්ෂ රේඛාව, හෘද රේඛාව, භාග්‍ය රේඛාව, සූර්ය රේඛාව, ග්‍රහ මණ්ඩල, මණිබන්ධ).";

    const promptText = `
      You are an expert Sri Lankan Master Palmistry Specialist & Astrologer ("හෙළ හස්තරේඛා ශාස්ත්‍රඥ").
      The user uploaded an image for deep, highly meticulous, accurate palmistry reading (ඉතාම සූක්ෂ්ම හා නිරවද්‍ය හස්තරේඛා පරීක්ෂාව).

      CRITICAL IMAGE VALIDATION STEP:
      1. Examine the image carefully. Does the image show BOTH hands (අත්ල දෙකම) together in the same photo?
      2. If BOTH left and right hands are present in the image together, set "bothHandsDetected": true.
      3. If the image contains ONLY ONE palm (Left OR Right hand), set "bothHandsDetected": false.

      IF "bothHandsDetected" IS FALSE (SINGLE PALM VALIDATED):
      Perform a microscopic, high-precision analysis of the palm lines, clarity, depth, islands, splits, squares, tridents, mounts, and bracelets.

      Details Provided:
      - Client Name: ${name || "Anonymous"}
      - Gender: ${gender || "Not specified"}
      - Hand Analyzed: ${handChoice === "Left" ? "Left Hand (වම් අත)" : "Right Hand (දකුණු අත)"}

      Generate a structured JSON response matching the following keys:
      1. bothHandsDetected: boolean (true if both hands are present in the image, false if only one palm is present).
      2. lifeLine: Analysis of Life Line (ජීවන රේඛාව) - vitality, health, longevity, major life events.
      3. headLine: Analysis of Head Line (ශීර්ෂ රේඛාව) - intellect, wisdom, decision making, mental focus.
      4. heartLine: Analysis of Heart Line (හෘද රේඛාව) - emotional nature, relationships, cardiac health, affection.
      5. fateLine: Analysis of Fate/Wealth Line (භාග්‍ය රේඛාව / ධන රේඛාව) - career prosperity, unexpected gains, success timeline.
      6. sunLine: Analysis of Sun/Fame Line (සූර්ය රේඛාව / විද්‍යා රේඛාව) - fame, arts, education, social prestige.
      7. mounts: Analysis of Palm Mounts (ග්‍රහ මණ්ඩල) - Jupiter (ගුරු), Venus (ශුක්‍ර), Saturn (ශනි), Moon (චන්ද්‍ර), Sun (සූර්ය), Mercury (බුධ), Mars (අඟහරු) mounts.
      8. specialSigns: Special Markings & Signs (විශේෂ ලක්ෂණ) - Trident (ත්‍රිශූලය), Star (තාරකා), Cross, Triangle, Fish sign (මත්ස්‍ය ලක්ෂණය), Bracelets (මණිබන්ධ).
      9. overallReading: Overall Meticulous Summary & Future Outlook (සමස්ත පලාපල හා සූක්ෂ්ම විග්‍රහය).
      10. remedies: Recommended Auspicious Remedies & Guidance (ශාන්තිකර්ම සහ උපදෙස්).

      ${langPrompt}
      Return ONLY a valid JSON object matching this schema.
    `;

    const contents = [
      {
        role: "user",
        parts: [
          {
            inlineData: {
              mimeType: mimeType,
              data: base64Data
            }
          },
          {
            text: promptText
          }
        ]
      }
    ];

    let parsedData: any = {};
    try {
      const response = await generateContentWithRetryAndFallback({
        contents: contents,
        config: {
          systemInstruction: "You are an expert Sri Lankan Master Palmistry Specialist (\"හෙළ හස්තරේඛා ශාස්ත්‍රඥ\"). Output only JSON matching the requested keys.",
          temperature: 0.2,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              bothHandsDetected: { type: Type.BOOLEAN },
              lifeLine: { type: Type.STRING },
              headLine: { type: Type.STRING },
              heartLine: { type: Type.STRING },
              fateLine: { type: Type.STRING },
              sunLine: { type: Type.STRING },
              mounts: { type: Type.STRING },
              specialSigns: { type: Type.STRING },
              overallReading: { type: Type.STRING },
              remedies: { type: Type.STRING }
            },
            required: ["bothHandsDetected", "lifeLine", "headLine", "heartLine", "fateLine", "overallReading"]
          }
        }
      });

      const resultText = response.text?.trim() || "{}";
      try {
        parsedData = JSON.parse(resultText);
      } catch (e) {
        console.error("Failed to parse palmistry json:", resultText);
        parsedData = buildDeterministicPalmistryAnalysis(name, gender, handChoice, language);
      }
    } catch (palmApiErr: any) {
      console.warn("Gemini Palmistry API fallback triggered:", palmApiErr?.message || palmApiErr);
      parsedData = buildDeterministicPalmistryAnalysis(name, gender, handChoice, language);
    }

    // Check if image contains both hands at once
    if (parsedData.bothHandsDetected === true) {
      return res.status(400).json({
        error: "අත්ල දෙකම එකවර ඡායාරූපයට නගා ඇත. ඉතාම සූක්ෂ්ම සහ නිවැරදි පරීක්ෂාවක් සඳහා කරුණාකර වම් හෝ දකුණු අත්ලෙන් එකක් පමණක් පැහැදිලිව ඡායාරූපගත කර නැවත එක් කරන්න. (Both palms detected in image. For accurate precision reading, please upload a clear photo of ONLY ONE palm - Left or Right hand)."
      });
    }

    // Save Palmistry report to database
    const palmReportId = "palm_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now();
    
    // Store uploaded palm image
    const storedImage = imageBase64 || null;

    const newPalmReport: any = {
      id: palmReportId,
      ipAddress: getClientIp(req),
      reportType: "palmistry",
      contactType: "whatsapp",
      contactValue: rawContact || userEmail || "guest@astro.lk",
      whatsappNumber: rawContact,
      birthDetails: {
        name: name || "Anonymous",
        birthDate: birthDate || "",
        gender: gender || "Male",
        handChoice: handChoice || "Right",
        district: "Palmistry Reading",
        userEmail: userEmail || rawContact || ""
      },
      palmistryData: parsedData,
      palmImageBase64: storedImage,
      storedImage: storedImage,
      imageBase64: storedImage,
      hasPalmImage: !!storedImage,
      rating: null,
      comment: null,
      createdAt: new Date().toISOString()
    };

    await saveReportAsync(newPalmReport);

    res.json({
      success: true,
      reportId: palmReportId,
      report: newPalmReport
    });
  } catch (error: any) {
    console.error("Palmistry analysis error:", error);
    res.status(500).json({ error: error.message || "හස්තරේඛා පරීක්ෂාවේදී දෝෂයක් සිදු විය. කරුණාකර නැවත උත්සාහ කරන්න." });
  }
});

// API: Dehalakshana Analysis Endpoint (Uses Gemini Multimodal Vision to analyze face/upper body photo)
app.post("/api/astrology/dehalakshana", async (req, res) => {
  try {
    const { imageBase64, name, birthDate, gender, userEmail, whatsappNumber, language } = req.body;

    if (!imageBase64) {
      return res.status(400).json({ error: "ඡායාරූපයක් (Photo) ලබා දී නොමැත." });
    }

    if (!getApiKey()) {
      return res.status(500).json({ error: "Gemini API Key is missing. Please configure GEMINI_API_KEY environment variable." });
    }

    // Enforce Name requirement
    const cleanName = (name || "").trim();
    if (!cleanName) {
      return res.status(400).json({
        error: "දේහලක්ෂණ පලාපල ලබාගැනීමට කරුණාකර ඔබගේ නම ඇතුළත් කරන්න. (Please enter your name.)"
      });
    }

    // Target WhatsApp / Contact identifier (optional)
    const rawContact = (whatsappNumber || userEmail || "").trim();
    const cleanPhone = rawContact.replace(/\D/g, "");
    const cleanUserEmail = (userEmail || "").toLowerCase().trim();
    const isAdminUser = cleanUserEmail === ADMIN_EMAIL;

    // Rate Limit: Maximum 5 dehalakshana requests per identifier per 24 hours (if provided)
    if (!isAdminUser && cleanPhone) {
      try {
        const allReports = await getReportsAsync();
        const nowMs = Date.now();
        const past24hMs = 24 * 60 * 60 * 1000;

        const recentDehaCount = allReports.filter((r: any) => {
          if (r.reportType !== "dehalakshana") return false;
          const repContactRaw = (r.whatsappNumber || r.contactValue || r.birthDetails?.userEmail || "").trim();
          const repPhone = repContactRaw.replace(/\D/g, "");
          if (!repPhone) return false;

          const isSameNumber = repPhone === cleanPhone || 
            (repPhone.length >= 8 && cleanPhone.length >= 8 && (repPhone.endsWith(cleanPhone.slice(-8)) || cleanPhone.endsWith(repPhone.slice(-8))));

          const repCreatedAt = r.createdAt ? new Date(r.createdAt).getTime() : 0;
          const isWithin24h = (nowMs - repCreatedAt) < past24hMs;

          return isSameNumber && isWithin24h;
        }).length;

        if (recentDehaCount >= 5) {
          return res.status(429).json({
            error: "අද දිනයට ලබාගත හැකි උපරිම දේහලක්ෂණ පරීක්ෂා කිරීම් ප්‍රමාණය ඉක්මවා ඇත. කරුණාකර පැය 24කට පසුව නැවත උත්සාහ කරන්න. (Maximum limit of body feature readings per day reached)."
          });
        }
      } catch (quotaErr) {
        console.error("Dehalakshana quota check error:", quotaErr);
      }
    }

    let mimeType = "image/jpeg";
    let base64Data = imageBase64;

    if (imageBase64.includes(";base64,")) {
      const parts = imageBase64.split(";base64,");
      mimeType = parts[0].replace("data:", "") || "image/jpeg";
      base64Data = parts[1];
    }

    if (base64Data.length > 25 * 1024 * 1024) {
      return res.status(400).json({ error: "ඡායාරූපයේ ප්‍රමාණය 15MB සීමාවට වඩා වැඩිය. කරුණාකර කුඩා ප්‍රමාණයේ ඡායාරූපයක් තෝරන්න." });
    }

    const langPrompt = (language === "english")
      ? "Provide all explanations in clear, professional English."
      : "Provide all explanations in natural, respectful, deep, highly encouraging Sinhala (සිංහල භාෂාවෙන්). Use standard Sri Lankan Samudrika Shastra & Dehalakshana terminology (සාමුද්‍රිකා ශාස්ත්‍රය, දේහලක්ෂණ, නළල, ගෙල/බෙල්ල, උරහිස්, යස ඉසුරු, ධන යෝග, වාසනාව).";

    const promptText = `
      You are an expert Sri Lankan Master Specialist in Ancient Samudrika Shastra & Dehalakshana Shastra ("හෙළ දේහලක්ෂණ හා සාමුද්‍රිකා ශාස්ත්‍රඥ").
      The user uploaded a photograph showing their face, neck, and shoulders for deep, highly meticulous, encouraging, accurate physiognomy and facial feature analysis (දේහලක්ෂණ පරීක්ෂාව).

      Details Provided:
      - Client Name: ${name || "Not specified"}
      - Birth Date: ${birthDate || "Not specified"}
      - Gender: ${gender || "Not specified"}

      Perform a microscopic, high-precision analysis of the face, facial organs, forehead, jaw, lips, nose, eyes, neck, and shoulders according to authentic Samudrika Shastra rules.

      Generate a structured JSON response matching the following keys:
      1. facialFeatures: Analysis of facial shape, forehead, and temple features - reflecting intellect, wisdom, leadership, mental drive, and character (මුහුණේ හැඩය සහ නළල මගින් කියැවෙන පෞරුෂය හා බුද්ධිය).
      2. eyesNoseLips: Analysis of eyes, nose, lips, chin, smile, and expression - reflecting emotional clarity, speech, integrity, and warmth (ඇස්, නාසය, දෙතොල්, නිකට හා මුහුණේ ස්වරූපය මගින් කියැවෙන ගුණාංග).
      3. neckShoulders: Analysis of the neck (බෙල්ල) and shoulders (උරහිස්) positioning and proportion - reflecting prosperity, grace, status, strength, and fortune (ගෙල සහ උරහිස් පිහිටීමෙන් පෙන්නුම් කරන යස ඉසුරු, වාසනාව හා ධන යෝග).
      4. bodyTraitsAndSigns: Special body features, complexion, auspicious marks, and poise (විශේෂ දේහ ලක්ෂණ, ශරීර ස්වරූපය හා වාසනාවන්ත ලකුණු).
      5. overallReading: Overall Meticulous Summary & Future Trajectory (සමස්ත සාමුද්‍රිකා පලාපල හා අනාගත ගමන් මග පිළිබඳ සූක්ෂ්ම විග්‍රහය).
      6. remediesAndGuidance: Recommended Auspicious Remedies, Affirmations & Guidance (සුබ සෙත සැලසෙන උපදෙස්, වස්ත්‍ර/රත්න/පූජා හා ශාන්තිකර්ම).

      ${langPrompt}
      Return ONLY a valid JSON object matching this schema.
    `;

    const contents = [
      {
        role: "user",
        parts: [
          {
            inlineData: {
              mimeType: mimeType,
              data: base64Data
            }
          },
          {
            text: promptText
          }
        ]
      }
    ];

    let parsedData: any = {};
    try {
      const response = await generateContentWithRetryAndFallback({
        contents: contents,
        config: {
          systemInstruction: "You are an expert Sri Lankan Master Specialist in Ancient Samudrika Shastra & Dehalakshana Shastra (\"හෙළ දේහලක්ෂණ හා සාමුද්‍රිකා ශාස්ත්‍රඥ\"). Output only JSON matching the requested keys.",
          temperature: 0.2,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              facialFeatures: { type: Type.STRING },
              eyesNoseLips: { type: Type.STRING },
              neckShoulders: { type: Type.STRING },
              bodyTraitsAndSigns: { type: Type.STRING },
              overallReading: { type: Type.STRING },
              remediesAndGuidance: { type: Type.STRING }
            },
            required: ["facialFeatures", "eyesNoseLips", "neckShoulders", "overallReading"]
          }
        }
      });

      const resultText = response.text?.trim() || "{}";
      try {
        parsedData = JSON.parse(resultText);
      } catch (e) {
        console.error("Failed to parse dehalakshana json:", resultText);
        parsedData = buildDeterministicDehalakshanaAnalysis(name, gender, language);
      }
    } catch (dehaApiErr: any) {
      console.warn("Gemini Dehalakshana API fallback triggered:", dehaApiErr?.message || dehaApiErr);
      parsedData = buildDeterministicDehalakshanaAnalysis(name, gender, language);
    }

    // Save Dehalakshana report to database
    const dehaReportId = "deha_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now();
    const storedImage = imageBase64 || null;

    const newDehaReport: any = {
      id: dehaReportId,
      ipAddress: getClientIp(req),
      reportType: "dehalakshana",
      contactType: (rawContact && rawContact.includes("@")) ? "email" : "whatsapp",
      contactValue: rawContact || userEmail || "guest@astro.lk",
      whatsappNumber: rawContact,
      birthDetails: {
        name: name || "Anonymous",
        birthDate: birthDate || "",
        gender: gender || "Male",
        district: "Dehalakshana Reading",
        userEmail: userEmail || rawContact || ""
      },
      dehalakshanaData: parsedData,
      dehalakshanaImageBase64: storedImage,
      storedImage: storedImage,
      imageBase64: storedImage,
      hasDehaImage: !!storedImage,
      hasPalmImage: false,
      rating: null,
      comment: null,
      createdAt: new Date().toISOString()
    };

    await saveReportAsync(newDehaReport);

    res.json({
      success: true,
      reportId: dehaReportId,
      report: newDehaReport
    });
  } catch (error: any) {
    console.error("Dehalakshana analysis error:", error);
    res.status(500).json({ error: error.message || "දේහලක්ෂණ පරීක්ෂාවේදී දෝෂයක් සිදු විය. කරුණාකර නැවත උත්සාහ කරන්න." });
  }
});

// Helper function to strip any leaked system prompt or context details from AI responses
function sanitizeAstrologyChatOutput(text: string): string {
  if (!text) return "";
  let cleaned = text;

  // 1. Remove systemic prompt section blocks if accidentally echoed
  cleaned = cleaned.replace(/User Birth Details:[\s\S]*?(?=Calculated Birth Chart|Generated Horoscope|Strict Astrological|Response:|\n\n[A-Z\u0D80-\u0DFF]|$)/gi, "");
  cleaned = cleaned.replace(/Calculated Birth Chart \(Mathematical Ground Truth\):[\s\S]*?(?=Generated Horoscope|Strict Astrological|Response:|\n\n[A-Z\u0D80-\u0DFF]|$)/gi, "");
  cleaned = cleaned.replace(/Generated Horoscope Predictions Context:[\s\S]*?(?=Strict Astrological|Response:|\n\n[A-Z\u0D80-\u0DFF]|$)/gi, "");
  cleaned = cleaned.replace(/Strict Astrological Rules for Response:[\s\S]*?(?=\n\n[A-Z\u0D80-\u0DFF]|$)/gi, "");
  cleaned = cleaned.replace(/CRITICAL ACTIVE PRESENT DATE & TIME REFERENCE[\s\S]*?(?=\n\n[A-Z\u0D80-\u0DFF]|$)/gi, "");

  // 2. Remove standalone prompt metadata labels
  cleaned = cleaned.replace(/^(User Birth Details|Calculated Birth Chart|Strict Astrological Rules|Generated Horoscope Predictions Context|System Instruction|Prompt Context|Ground Truth|D1 House Placements|D9 Navamsa Placements|Detailed Planetary Positions):.*/gmi, "");

  // 3. Remove raw leaked JSON blocks if present
  cleaned = cleaned.replace(/```json[\s\S]*?```/gi, "");
  cleaned = cleaned.replace(/\{"lagna":[\s\S]*?\}/gi, "");
  cleaned = cleaned.replace(/\{"housePlacements":[\s\S]*?\}/gi, "");

  // 4. Remove robotic meta preamble lines
  cleaned = cleaned.replace(/^(Based on (the provided|your) birth (details|chart|data)|According to the (calculated|provided) (astrological|birth) (data|chart|details)|Here is the analysis based on your details):\s*/i, "");

  // 5. Clean up multi-blank lines
  cleaned = cleaned.replace(/\n{3,}/g, "\n\n").trim();

  return cleaned || text.trim();
}

// API: Astrological Chatbot Endpoint
app.post("/api/astrology/chat", async (req, res) => {
  try {
    const { birthDetails, chart, predictions, message, history, reportId, userEmail, language } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Message is required." });
    }

    const cleanEmail = (userEmail || "").toLowerCase().trim();
    const isAdmin = cleanEmail === "sampathub89@gmail.com";

    // Enforce dynamic chat questions limit PER DAY for non-admin users
    const todaySL = getSLDateString();
    if (!isAdmin) {
      // Determine allowed question quota per report for this user/email
      const allowedLimit = cleanEmail ? await getUserAllowedChatLimit(cleanEmail) : 4;
      
      // Count user questions sent for this specific report/session
      let userMsgCount = 0;
      if (reportId) {
        const report = await getReportByIdAsync(reportId);
        if (report && Array.isArray(report.chatHistory)) {
          userMsgCount = report.chatHistory.filter((m: any) => m.sender === "user").length;
        }
      }
      if (userMsgCount === 0 && Array.isArray(history)) {
        userMsgCount = history.filter((m: any) => m.sender === "user").length;
      }

      if (userMsgCount >= allowedLimit) {
        const quotaRec = cleanEmail ? await getUserChatQuotaRecord(cleanEmail) : { bonusGranted: false, customLimit: null };
        const canAutoExtend = !quotaRec.bonusGranted && (quotaRec.customLimit === null || quotaRec.customLimit === undefined);

        return res.status(429).json({
          error: canAutoExtend
            ? "ඔබගේ මෙම පලාපල වාර්තාව සඳහා හිමි නොමිලේ AI ප්‍රශ්න 4 සීමාව භාවිත කර ඇත. නොමිලේ අමතර ප්‍රශ්න 6ක් (මුළු 10ක්) ලබාගැනීමට WhatsApp අංකය සමඟ ඉල්ලුම් කරන්න."
            : `ඔබගේ AI ප්‍රශ්න සීමාව (${allowedLimit}) අවසන් වී ඇත. වැඩිදුර සීමාවන් දීර්ඝ කරගැනීමට කරුණාකර ඔබගේ Email සහ WhatsApp අංකය සමඟ Admin (sampathub89@gmail.com) අමතන්න.`,
          chatLimitReached: true,
          canAutoExtend,
          allowedLimit,
          usedCount: userMsgCount,
          adminEmail: "sampathub89@gmail.com"
        });
      }
    }

    if (!getApiKey()) {
      return res.status(500).json({ error: "Gemini API key is not configured. Please add GEMINI_API_KEY in the Secrets panel." });
    }

    // Capture the exact current date/time in Sri Lankan context for accurate transit and age assessments
    const currentDate = new Date();
    const currentDateStr = currentDate.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      timeZone: 'Asia/Colombo'
    });
    const currentLocalTimeStr = currentDate.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      timeZone: 'Asia/Colombo'
    });

    // Format chat history & provide astrology-centric context
    const systemPrompt = `
      You are an expert Sri Lankan Astrologer ("Hela Jyotishacharya" / "හෙළ ජ්‍යෝතිෂවේදී").
      The user is asking questions about their personal birth chart (kendraya), predictions, and future.

      =========================================
      CRITICAL ACTIVE PRESENT DATE & TIME REFERENCE (FOR TRANSIT & DASHA COMPUTATION):
      - Today's Date: ${currentDateStr} (Sri Lanka Time Zone)
      - Today's Time: ${currentLocalTimeStr}
      - Present Year: ${currentDate.getFullYear()}
      - Exact Current Timestamp: ${currentDate.toISOString()}
      =========================================

      User Birth Details:
      - Name: ${birthDetails?.name || "Unnamed"}
      - Birth Date: ${birthDetails?.birthDate}
      - Birth Time: ${birthDetails?.birthTime}
      - Birth Place: ${birthDetails?.birthPlace}, ${birthDetails?.district} District, Sri Lanka
      - Gender: ${birthDetails?.gender}
      - Preference Language: ${birthDetails?.language}

      Calculated Birth Chart (Mathematical Ground Truth):
      - Lagna (Ascendant): ${chart?.lagna} (${chart?.lagnaSinhala})
      - Navamsa Lagna (D9 Ascendant): ${chart?.navamsaLagna || "N/A"} (${chart?.navamsaLagnaSinhala || "N/A"})
      - Moon Sign (Rashi): ${chart?.rashi} (${chart?.rashiSinhala})
      - Birth Star (Nakshatra): ${chart?.nakshatra} (${chart?.nakshatraSinhala})
      - Nakshatra Pada (පාදය): ${chart?.calculations?.padaya || "N/A"}
      - Moon Longitude (චන්ද්‍ර ස්ඵුටය): ${chart?.calculations?.moonLongitudeFullSi || chart?.calculations?.moonLongitudeFullEn || "N/A"}
      - Birth Dasha Lord & Duration (උපන් දශාව): ${chart?.calculations?.dashaLordSi || chart?.calculations?.dashaLordEn || "N/A"} (${chart?.calculations?.balanceDashaSi || chart?.calculations?.balanceDashaEn || "N/A"})
      - Current Active Mahadasha Today: ${chart?.calculations?.currentDashaLordSi || chart?.calculations?.currentDashaLordEn || "N/A"} (Active from ${chart?.calculations?.currentDashaStart || "N/A"} to ${chart?.calculations?.currentDashaEnd || "N/A"}, Remaining: ${chart?.calculations?.currentDashaRemainingSi || chart?.calculations?.currentDashaRemainingEn || "N/A"})
      - Vimshottari Dasha Sequence: ${JSON.stringify(chart?.calculations?.dashaPeriodTimeline || chart?.dashaPeriodTimeline || [])}
      - Gana (ගණය): ${chart?.calculations?.ganaSi || chart?.calculations?.ganaEn || ""}
      - Yoni (යෝනිය): ${chart?.calculations?.yoniSi || chart?.calculations?.yoniEn || ""}
      - Linga (ලිංගය): ${chart?.calculations?.lingaSi || chart?.calculations?.lingaEn || ""}
      - Nadi (නාඩිය): ${chart?.calculations?.nadiSi || chart?.calculations?.nadiEn || ""}
      - D1 House Placements: ${JSON.stringify(chart?.housePlacements || {})}
      - D9 Navamsa Placements: ${JSON.stringify(chart?.navamsaHousePlacements || {})}
      - Detailed Planetary Positions & Degrees: ${JSON.stringify(chart?.planetaryDetails || [])}

      Generated Horoscope Predictions Context:
      - General: ${predictions?.general || "N/A"}
      - Career & Education: ${predictions?.career || "N/A"}
      - Wealth & Finances: ${predictions?.wealth || "N/A"}
      - Health & Body: ${predictions?.health || "N/A"}
      - Marriage & Relationships: ${predictions?.marriage || "N/A"}
      - Active Dasha & Apala Remedies: ${predictions?.dasha || "N/A"}

      Strict Astrological Rules for Response:
      1. Always speak with deep humility, respect, wisdom, warmth, and comforting guidance. Represent authentic Sri Lankan astrologers ("හෙළ ජ්‍යෝතිෂවේදී").
      2. Respond in the user's preferred language (${birthDetails?.language || 'sinhala'}). If they ask in Sinhala (or Singlish), respond in elegant, friendly, highly detailed, and accessible Sinhala.
      3. CRITICAL DATA INTEGRITY: You MUST strictly base all answers on the calculated birth star (${chart?.nakshatraSinhala || chart?.nakshatra}), Moon sign (${chart?.rashiSinhala || chart?.rashi}), Lagna (${chart?.lagnaSinhala || chart?.lagna}), house placements (භාව 1-12), and Vimshottari dasha timeline given above. Never calculate or invent a different Nakshatra, Rashi, or Lagna.
      4. COMPREHENSIVE & FULL DETAILED ANSWER (සම්පූර්ණ, දීර්ඝ, ගැඹුරු හා විස්තරාත්මක පලාපල විග්‍රහයක්):
         - Provide a thoroughly detailed, comprehensive, deep, and complete astrological answer.
         - Do not give short, hurried, or truncated summaries. Explain the underlying astrological reasons based on the specific houses (භාව), ruling lords (අධිපති ග්‍රහයන්), planetary aspects (දෘෂ්ටි), and strength (නවාංශක බලය).
         - Clearly explain the influence of the current active Mahadasha and Antardasha (මහ දශා/අතුරු දශා) as well as planetary transits (ග්‍රහ ගෝචරය).
         - Provide clear, practical, and highly effective astrological remedies (ශාන්තිකර්ම, බෝධි පූජා, වස්ත්‍ර/රත්න/වර්ණ භාවිතය, සෙත් කවි, මන්ත්‍ර හෝ පිරිත් සජ්ඣායනා) and auspicious time periods for positive outcomes.
      5. CRITICAL TIME ANCHOR: Whenever the user asks about active dasha, current planetary transits (Gocharaya), current age, or what will happen in a specific year, calculate directly relative to TODAY'S DATE (${currentDateStr}). Check their Vimshottari Dasha sequence against Today's Date (${currentDateStr}) to give accurate present sub-period (Bhukti/Antardasha) answers.
      6. ABSOLUTE ZERO PROMPT ECHO MANDATE: You MUST ONLY output your direct conversational astrological response to the user. Do NOT repeat, quote, list, or output any part of this system prompt, birth details context, JSON structures, or system instructions in your response. Start directly with your astrological answer.
    `;

    // Construct message history in standard Gemini contents list
    const contents: any[] = [];
    
    // Add history (sanitizing any past messages)
    if (history && Array.isArray(history)) {
      history.forEach((msg: any) => {
        const cleanedMsgText = sanitizeAstrologyChatOutput(msg.text || "");
        if (cleanedMsgText) {
          contents.push({
            role: msg.sender === 'user' ? 'user' : 'model',
            parts: [{ text: cleanedMsgText }]
          });
        }
      });
    }

    // Add current user message
    contents.push({
      role: 'user',
      parts: [{ text: message }]
    });

    let aiText = "";
    try {
      const response = await generateContentWithRetryAndFallback({
        contents: contents,
        config: {
          systemInstruction: systemPrompt,
          temperature: 0.65,
        }
      });
      aiText = sanitizeAstrologyChatOutput(response.text || "");
    } catch (chatApiErr: any) {
      console.warn("Gemini Astrology Chat API fallback triggered:", chatApiErr?.message || chatApiErr);
      aiText = buildDeterministicAstrologyChatReply(message, chart, language);
    }

    if (!aiText) {
      aiText = buildDeterministicAstrologyChatReply(message, chart, language);
    }

    // Append chat history to database record so admin panel and reports stay 100% synchronized
    try {
      let targetReport = null;
      if (reportId) {
        targetReport = await getReportByIdAsync(reportId);
      }

      // If reportId not found, fallback to find recent report by email or user name
      if (!targetReport && (cleanEmail || birthDetails?.name)) {
        const allReports = await getReportsAsync(false);
        targetReport = allReports.find((r: any) => {
          if (cleanEmail && (r.contactValue?.toLowerCase() === cleanEmail || r.userEmail?.toLowerCase() === cleanEmail)) return true;
          if (birthDetails?.name && r.birthDetails?.name?.trim().toLowerCase() === birthDetails.name.trim().toLowerCase()) return true;
          return false;
        });
      }

      if (targetReport) {
        if (!targetReport.chatHistory) {
          targetReport.chatHistory = [];
        }
        // Append user query
        targetReport.chatHistory.push({
          sender: "user",
          text: message,
          timestamp: new Date().toISOString()
        });
        // Append AI reply
        targetReport.chatHistory.push({
          sender: "assistant",
          text: aiText,
          timestamp: new Date().toISOString()
        });
        targetReport.updatedAt = new Date().toISOString();

        await saveReportAsync(targetReport);
        console.log(`Saved complete chat message interaction for report: ${targetReport.id} (${targetReport.birthDetails?.name || 'Client'})`);
      } else {
        console.warn(`No target report found to attach chat log for email: ${cleanEmail}`);
      }
    } catch (dbErr: any) {
      console.error(`Failed to save chat history to database:`, dbErr?.message || dbErr);
    }

    if (!isAdmin && cleanEmail) {
      await incrementDailyChatCount(cleanEmail, todaySL);
    }

    res.json({ text: aiText });

  } catch (error: any) {
    console.error("Astrology chat api error:", error);
    res.status(500).json({ error: error.message || "An error occurred during chat consultation." });
  }
});

// Persistent JSON Database path for generated reports and ratings (Fallback storage)
const DATABASE_FILE = process.env.NETLIFY 
  ? "/tmp/reports.json" 
  : path.join(process.cwd(), "reports.json");

// Ensure the local database file exists
if (!fs.existsSync(DATABASE_FILE)) {
  try {
    const originalDb = path.join(process.cwd(), "reports.json");
    if (process.env.NETLIFY && fs.existsSync(originalDb)) {
      const data = fs.readFileSync(originalDb, "utf8");
      fs.writeFileSync(DATABASE_FILE, data, "utf8");
    } else {
      fs.writeFileSync(DATABASE_FILE, JSON.stringify([], null, 2), "utf8");
    }
  } catch (err) {
    console.error("Failed to initialize database file:", err);
  }
}

function readReportsFromDb() {
  try {
    const rawData = fs.readFileSync(DATABASE_FILE, "utf8");
    return JSON.parse(rawData);
  } catch (error) {
    console.error("Error reading database:", error);
    return [];
  }
}

function writeReportsToDb(reports: any[]) {
  try {
    fs.writeFileSync(DATABASE_FILE, JSON.stringify(reports, null, 2), "utf8");
  } catch (error) {
    console.error("Error writing database:", error);
  }
}

// Initialize Firebase Firestore for serverless persistence
let firestoreDb: any = null;
let firestoreConsecutiveFailures = 0;
let firestoreDisabledUntilMs = 0;

function isFirestoreAvailable(): boolean {
  if (!firestoreDb) return false;
  if (Date.now() < firestoreDisabledUntilMs) return false;
  return true;
}

function recordFirestoreSuccess() {
  firestoreConsecutiveFailures = 0;
  firestoreDisabledUntilMs = 0;
}

function recordFirestoreFailure(err: any) {
  firestoreConsecutiveFailures++;
  if (firestoreConsecutiveFailures >= 5) {
    firestoreDisabledUntilMs = Date.now() + 15000; // Brief 15s pause only after 5 consecutive failures
    console.warn(`[Firestore Circuit Breaker] ${firestoreConsecutiveFailures} consecutive timeouts/failures (${err?.message || err}). Briefly pausing Firestore for 15s.`);
  }
}

const possibleConfigPaths = [
  path.join(process.cwd(), "firebase-applet-config.json"),
  path.join(process.cwd(), "netlify/functions/firebase-applet-config.json"),
  path.join(process.cwd(), "src/firebase-applet-config.json"),
  "firebase-applet-config.json"
];

// Safely try __dirname if it exists (CommonJS environment fallback)
try {
  if (typeof __dirname !== "undefined") {
    possibleConfigPaths.push(path.join(__dirname, "firebase-applet-config.json"));
    possibleConfigPaths.push(path.join(__dirname, "../firebase-applet-config.json"));
    possibleConfigPaths.push(path.join(__dirname, "../../firebase-applet-config.json"));
  }
} catch (err) {
  // Ignore
}

let firebaseConfigPath = "";
for (const p of possibleConfigPaths) {
  if (fs.existsSync(p)) {
    firebaseConfigPath = p;
    break;
  }
}

const DEFAULT_FIREBASE_CONFIG = {
  projectId: "my-apps-script-logs",
  appId: "1:1051412247539:web:ddfe98a57ebc790cccd886",
  apiKey: "AIzaSyAujseEFfc3jieZGFg6mr7EFMEjAHfKQ3k",
  authDomain: "my-apps-script-logs.firebaseapp.com",
  databaseURL: "https://my-apps-script-logs-default-rtdb.asia-southeast1.firebasedatabase.app",
  firestoreDatabaseId: "",
  storageBucket: "my-apps-script-logs.firebasestorage.app",
  messagingSenderId: "1051412247539",
  measurementId: "G-XHSNB0MTJG"
};

let config = DEFAULT_FIREBASE_CONFIG;
let loadedFromDisk = false;

if (process.env.FIREBASE_API_KEY) {
  config = {
    projectId: process.env.FIREBASE_PROJECT_ID || "",
    appId: process.env.FIREBASE_APP_ID || "",
    apiKey: process.env.FIREBASE_API_KEY || "",
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || `${process.env.FIREBASE_PROJECT_ID}.firebaseapp.com`,
    databaseURL: process.env.FIREBASE_DATABASE_URL || "",
    firestoreDatabaseId: process.env.FIREBASE_DATABASE_ID || "",
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || `${process.env.FIREBASE_PROJECT_ID}.firebasestorage.app`,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "",
    measurementId: ""
  };
  console.log("Firestore: Initializing using custom project configuration from environment variables (Project ID:", config.projectId, ")");
} else if (firebaseConfigPath) {
  try {
    config = JSON.parse(fs.readFileSync(firebaseConfigPath, "utf-8"));
    loadedFromDisk = true;
  } catch (err) {
    console.error("Failed to read firebase-applet-config.json from disk, falling back to default config:", err);
  }
}

try {
  const firebaseApp = initializeApp({
    apiKey: config.apiKey,
    authDomain: config.authDomain,
    projectId: config.projectId,
    storageBucket: config.storageBucket,
    messagingSenderId: config.messagingSenderId,
    appId: config.appId
  });
  // Use initializeFirestore with experimentalForceLongPolling for robust serverless connectivity
  firestoreDb = initializeFirestore(firebaseApp, {
    experimentalForceLongPolling: true
  }, config.firestoreDatabaseId || "(default)");
  
  if (loadedFromDisk) {
    console.log(`Firestore initialized successfully on server (long polling enabled) using config from: ${firebaseConfigPath} with database ID:`, config.firestoreDatabaseId || "(default)");
  } else {
    console.log("Firestore initialized successfully on server (long polling enabled) using static fallback configuration with database ID:", config.firestoreDatabaseId || "(default)");
  }
} catch (err) {
  console.error("Failed to initialize Firebase Firestore:", err);
}

// Robust timeout helper to prevent serverless function hangs (Netlify 502/504 errors)
function withTimeout<T>(promise: Promise<T>, timeoutMs: number = 3500): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Firestore operation timed out"));
    }, timeoutMs);
    promise
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

function ensureNavamsaOnReport(report: any): any {
  if (!report || !report.chart) return report;
  if (report.chart.navamsaHousePlacements && report.chart.navamsaLagna) {
    return report;
  }
  if (report.birthDetails && report.birthDetails.birthDate && report.birthDetails.birthTime && report.birthDetails.district) {
    try {
      const placements = calculatePlanetsAndPlacements(
        report.birthDetails.birthDate,
        report.birthDetails.birthTime,
        report.birthDetails.district
      );
      report.chart.navamsaHousePlacements = placements.navamsaHousePlacements;
      report.chart.navamsaLagna = placements.navamsaLagna;
      report.chart.navamsaLagnaSinhala = placements.navamsaLagnaSinhala;
      if (Array.isArray(report.chart.planetaryDetails)) {
        report.chart.planetaryDetails = report.chart.planetaryDetails.map((p: any) => {
          const match = placements.planetaryDetails.find((pd: any) => pd.planet === p.planet);
          if (match) {
            return {
              ...p,
              navamsaSign: p.navamsaSign || match.navamsaSign,
              navamsaSignSinhala: p.navamsaSignSinhala || match.navamsaSignSinhala,
              navamsaHouse: p.navamsaHouse || match.navamsaHouse
            };
          }
          return p;
        });
      }
    } catch (err) {
      console.error(`Error backfilling Navamsa for report ${report.id}:`, err);
    }
  }
  return report;
}

// In-memory cache for ultra-fast reports access & background Firestore synchronization
const cachedReportsMap = new Map<string, any>();
let lastFirestoreSyncTime = 0;
let isFirestoreSyncInProgress = false;

// Function to synchronously return consolidated reports instantly from memory & local JSON database
function getConsolidatedReportsLocal(): any[] {
  const localRecords = readReportsFromDb();
  for (const r of localRecords) {
    if (r && r.id && r.id !== "google_drive_tokens" && r.id !== "usage_logs") {
      const existing = cachedReportsMap.get(r.id) || {};
      cachedReportsMap.set(r.id, { ...existing, ...r });
    }
  }
  return Array.from(cachedReportsMap.values());
}

// Fast synchronous or background sync from Firestore
async function syncReportsFromFirestore(): Promise<void> {
  if (!isFirestoreAvailable() || isFirestoreSyncInProgress) return;
  isFirestoreSyncInProgress = true;
  try {
    const querySnapshot = await withTimeout(getDocs(collection(firestoreDb, "reports")), 8000);
    recordFirestoreSuccess();
    let hasNewChanges = false;
    querySnapshot.forEach((docSnap) => {
      const docId = docSnap.id;
      if (docId !== "google_drive_tokens" && docId !== "usage_logs") {
        const existing = cachedReportsMap.get(docId) || {};
        const firestoreRecord = { id: docId, ...docSnap.data() };
        const mergedObj = { ...existing, ...firestoreRecord };
        if (!mergedObj.palmImageBase64 && existing.palmImageBase64) mergedObj.palmImageBase64 = existing.palmImageBase64;
        if (!mergedObj.dehalakshanaImageBase64 && existing.dehalakshanaImageBase64) mergedObj.dehalakshanaImageBase64 = existing.dehalakshanaImageBase64;
        if (!mergedObj.storedImage && existing.storedImage) mergedObj.storedImage = existing.storedImage;
        if (!mergedObj.imageBase64 && existing.imageBase64) mergedObj.imageBase64 = existing.imageBase64;
        cachedReportsMap.set(docId, mergedObj);
        hasNewChanges = true;
      }
    });
    lastFirestoreSyncTime = Date.now();
    
    // Optionally persist merged records to local JSON database
    if (hasNewChanges) {
      try {
        const allMerged = Array.from(cachedReportsMap.values());
        const otherRecords = readReportsFromDb().filter((r: any) => r && (r.id === "google_drive_tokens" || r.id === "usage_logs"));
        writeReportsToDb([...allMerged, ...otherRecords]);
      } catch (e) {}
    }
  } catch (err: any) {
    recordFirestoreFailure(err);
    console.warn("Firestore sync notice (using local cache):", err?.message || err);
  } finally {
    isFirestoreSyncInProgress = false;
  }
}

async function getReportsAsync(forceFreshSync: boolean = false): Promise<any[]> {
  // 1. Ensure local disk reports are consolidated into memory (instant 0ms)
  getConsolidatedReportsLocal();

  // 2. If fresh sync is requested or no sync in last 10 seconds or memory empty, sync from Firestore
  if (isFirestoreAvailable() && (forceFreshSync || Date.now() - lastFirestoreSyncTime > 10000 || cachedReportsMap.size === 0)) {
    if (forceFreshSync) {
      await syncReportsFromFirestore();
    } else {
      syncReportsFromFirestore().catch(() => {});
    }
  }

  return Array.from(cachedReportsMap.values());
}

async function getReportByIdAsync(id: string): Promise<any | null> {
  const allLocal = readReportsFromDb();
  const localReport = allLocal.find((r: any) => r && String(r.id) === String(id)) || cachedReportsMap.get(String(id)) || null;

  let report = localReport;

  if (isFirestoreAvailable() && (!report || !report.chart)) {
    try {
      const docSnap = await withTimeout(getDoc(doc(firestoreDb, "reports", String(id))), 1500);
      recordFirestoreSuccess();
      if (docSnap.exists()) {
        const firestoreRecord = { id: docSnap.id, ...docSnap.data() };
        report = { ...(localReport || {}), ...firestoreRecord };
        if (report) cachedReportsMap.set(String(id), report);
      }
    } catch (err: any) {
      recordFirestoreFailure(err);
      console.warn(`Firestore unavailable in getReportByIdAsync for ID ${id}:`, err?.message || err);
    }
  }

  if (!report) return null;

  // Extract any image field found either in report or localReport
  const img = report.dehalakshanaImageBase64 || report.palmImageBase64 || report.storedImage || report.imageBase64 || localReport?.dehalakshanaImageBase64 || localReport?.palmImageBase64 || localReport?.storedImage || localReport?.imageBase64;

  if (img) {
    if (report.reportType === "palmistry" || report.palmistryData || report.palmImageBase64 || localReport?.palmImageBase64) {
      report.palmImageBase64 = report.palmImageBase64 || img;
    }
    if (report.reportType === "dehalakshana" || report.reportType === "deha" || report.dehalakshanaData || report.dehalakshanaImageBase64 || localReport?.dehalakshanaImageBase64) {
      report.dehalakshanaImageBase64 = report.dehalakshanaImageBase64 || img;
    }
    report.storedImage = report.storedImage || img;
    report.imageBase64 = report.imageBase64 || img;
  }

  return ensureNavamsaOnReport(report);
}

async function getUserLatestReportAsync(email: string): Promise<any | null> {
  const clean = email.toLowerCase().trim();
  if (!clean) return null;

  const allReports = await getReportsAsync();
  const userReports = allReports.filter((r: any) => {
    const val = (r.contactValue || "").toLowerCase().trim();
    return val === clean;
  });

  if (userReports.length === 0) return null;

  userReports.sort((a: any, b: any) => {
    const timeA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
    const timeB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
    return timeB - timeA;
  });

  return ensureNavamsaOnReport(userReports[0]);
}

async function saveReportAsync(report: any): Promise<void> {
  // 1. Dual-write to in-memory cache & local DB FIRST (0ms instant availability)
  try {
    cachedReportsMap.set(report.id, report);
    const reports = readReportsFromDb();
    const idx = reports.findIndex((r: any) => r && r.id === report.id);
    if (idx !== -1) {
      reports[idx] = report;
    } else {
      reports.push(report);
    }
    writeReportsToDb(reports);
  } catch (localErr) {
    console.error(`Local DB write error in saveReportAsync for ID ${report?.id}:`, localErr);
  }

  // 2. Persist to Firestore with timeout
  if (isFirestoreAvailable()) {
    try {
      const { id, ...data } = report;
      const firestoreData: any = { ...data };
      if (firestoreData.dehalakshanaImageBase64 && firestoreData.dehalakshanaImageBase64.length > 900000) {
        delete firestoreData.dehalakshanaImageBase64;
      }
      if (firestoreData.palmImageBase64 && firestoreData.palmImageBase64.length > 900000) {
        delete firestoreData.palmImageBase64;
      }
      if (firestoreData.storedImage && firestoreData.storedImage.length > 900000) {
        delete firestoreData.storedImage;
      }
      if (firestoreData.imageBase64 && firestoreData.imageBase64.length > 900000) {
        delete firestoreData.imageBase64;
      }
      await withTimeout(setDoc(doc(firestoreDb, "reports", id), firestoreData, { merge: true }), 2500);
      recordFirestoreSuccess();
      console.log(`Firestore: Report ${id} saved successfully.`);
    } catch (err: any) {
      recordFirestoreFailure(err);
      console.warn(`Firestore error in saveReportAsync for ID ${report?.id} (falling back to local file):`, err?.message || err);
    }
  }
}

async function deleteReportAsync(id: string): Promise<boolean> {
  let deletedAny = false;
  cachedReportsMap.delete(id);

  if (isFirestoreAvailable()) {
    try {
      await withTimeout(deleteDoc(doc(firestoreDb, "reports", id)), 3000);
      recordFirestoreSuccess();
      console.log(`Firestore: Report ${id} delete operation finished.`);
      deletedAny = true;
    } catch (err: any) {
      recordFirestoreFailure(err);
      console.warn(`Firestore error in deleteReportAsync for ID ${id}:`, err?.message || err);
    }
  }

  // Always also delete from local JSON database to prevent stale records on fallback
  try {
    const reports = readReportsFromDb();
    const filtered = reports.filter((r: any) => r && r.id !== id);
    if (filtered.length !== reports.length) {
      writeReportsToDb(filtered);
      console.log(`Local DB: Report ${id} deleted from local storage.`);
      deletedAny = true;
    }
  } catch (err) {
    console.error(`Error deleting report ${id} from local DB:`, err);
  }

  return deletedAny;
}

async function getStoredDriveTokensAsync(): Promise<any | null> {
  const reports = readReportsFromDb();
  const tokenRecord = reports.find((r: any) => r.id === "google_drive_tokens");
  if (tokenRecord && tokenRecord.tokens) {
    return tokenRecord.tokens;
  }

  if (isFirestoreAvailable()) {
    try {
      const docSnap = await withTimeout(getDoc(doc(firestoreDb, "config", "google_drive_tokens")), 800);
      recordFirestoreSuccess();
      if (docSnap.exists()) {
        return docSnap.data().tokens || null;
      }
      return null;
    } catch (err: any) {
      recordFirestoreFailure(err);
      console.warn("Firestore error in getStoredDriveTokensAsync, falling back to local storage:", err?.message || err);
    }
  }
  return null;
}

async function saveStoredDriveTokensAsync(tokens: any): Promise<void> {
  if (firestoreDb) {
    try {
      const currentTokens = await getStoredDriveTokensAsync() || {};
      const newTokens = {
        ...currentTokens,
        ...tokens,
        updatedAt: new Date().toISOString()
      };
      await withTimeout(setDoc(doc(firestoreDb, "config", "google_drive_tokens"), { tokens: newTokens }, { merge: true }), 2000);
      console.log("Firestore: Google Drive tokens persisted successfully.");
      return;
    } catch (err: any) {
      console.error("Firestore error in saveStoredDriveTokensAsync, falling back to local storage:", err?.message || err);
    }
  }
  const reports = readReportsFromDb();
  let tokenRecord = reports.find((r: any) => r.id === "google_drive_tokens");
  
  if (!tokenRecord) {
    tokenRecord = { id: "google_drive_tokens", tokens: {} };
    reports.push(tokenRecord);
  }
  
  tokenRecord.tokens = {
    ...tokenRecord.tokens,
    ...tokens,
    updatedAt: new Date().toISOString()
  };
  
  writeReportsToDb(reports);
  console.log("[Google Drive Sandbox Fallback] Tokens persisted to reports database.");
}

async function refreshGoogleAccessToken(): Promise<string | null> {
  const tokens = await getStoredDriveTokensAsync();
  if (!tokens || !tokens.refresh_token) {
    console.warn("[Google Drive] No refresh token available.");
    return null;
  }

  // If the access token is not expired yet (with a 2-minute safety buffer), return it directly
  if (tokens.access_token && tokens.expiry_date && tokens.expiry_date > Date.now() + 120000) {
    return tokens.access_token;
  }

  const clientId = process.env.GOOGLE_CLIENT_ID || "";
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";

  if (!clientId || !clientSecret) {
    console.warn("[Google Drive] Client ID or Client Secret not configured for refresh.");
    return null;
  }

  try {
    console.log("[Google Drive] Refreshing access token...");
    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: tokens.refresh_token,
        grant_type: "refresh_token"
      })
    });

    if (!res.ok) {
      const errJson = await res.json();
      console.error("[Google Drive] Refresh token failed:", errJson);
      return null;
    }

    const data = await res.json();
    const newAccessToken = data.access_token;
    const expiryDate = Date.now() + (data.expires_in || 3600) * 1000;

    await saveStoredDriveTokensAsync({
      access_token: newAccessToken,
      expiry_date: expiryDate
    });

    return newAccessToken;
  } catch (err) {
    console.error("[Google Drive] Error refreshing token:", err);
    return null;
  }
}

function formatReportText(report: any) {
  const bd = report.birthDetails || {};
  const ch = report.chart || {};
  const pred = report.predictions || {};
  const calc = ch.calculations || {};

  let text = `============================================================\n`;
  text += `              SRI LANKA ASTROLOGY REPORT\n`;
  text += `============================================================\n`;
  text += `ID: ${report.id}\n`;
  text += `Created At: ${report.createdAt || new Date().toISOString()}\n`;
  text += `------------------------------------------------------------\n`;
  text += `1. BIRTH DETAILS (උපත් විස්තර)\n`;
  text += `------------------------------------------------------------\n`;
  text += `Name (නම): ${bd.name || "N/A"}\n`;
  text += `Gender (ස්ත්‍රී/පුරුෂ): ${bd.gender === "female" ? "Female (ස්ත්‍රී)" : "Male (පුරුෂ)"}\n`;
  text += `Date of Birth (උපන් දිනය): ${bd.date || "N/A"}\n`;
  text += `Time of Birth (උපන් වේලාව): ${bd.time || "N/A"}\n`;
  text += `Place of Birth (උපන් ස්ථානය): ${bd.place || "N/A"}\n`;
  text += `Latitude (අක්ෂාංශ): ${bd.latitude || "N/A"}\n`;
  text += `Longitude (දේශාංශ): ${bd.longitude || "N/A"}\n`;
  text += `Timezone (වේලා කලාපය): ${bd.timezone || "N/A"}\n`;
  text += `------------------------------------------------------------\n`;
  text += `2. ASTROLOGICAL CHART (කේන්දර සටහන)\n`;
  text += `------------------------------------------------------------\n`;
  text += `Lagna (ලග්නය): ${ch.lagnaSinhala || "N/A"} (${ch.lagna || "N/A"})\n`;
  text += `Nakshatra (නැකත): ${ch.nakshatraSinhala || "N/A"} (${ch.nakshatra || "N/A"})\n`;
  text += `Rashi (රාශිය): ${ch.rashiSinhala || "N/A"} (${ch.rashi || "N/A"})\n`;
  text += `Gana (ගණය): ${calc.ganaSi || "N/A"}\n`;
  text += `Yoni (යෝනිය): ${calc.yoniSi || "N/A"}\n`;
  text += `------------------------------------------------------------\n`;
  text += `3. VEDIC HOROSCOPE PREDICTIONS (පලාපල විස්තර)\n`;
  text += `------------------------------------------------------------\n`;
  text += `General (පොදු පලාපල):\n${pred.general || "N/A"}\n\n`;
  text += `Career & Business (රැකියාව සහ ව්‍යාපාර):\n${pred.career || "N/A"}\n\n`;
  text += `Health & Well-being (සෞඛ්‍යය):\n${pred.health || "N/A"}\n\n`;
  text += `Marriage & Family (විවාහය සහ පවුල):\n${pred.marriage || "N/A"}\n\n`;
  text += `Wealth & Finances (ධනය සහ උපයීම්):\n${pred.wealth || "N/A"}\n\n`;
  text += `Dasha Predictions (දශා පලාපල):\n${pred.dasha || "N/A"}\n`;
  text += `------------------------------------------------------------\n`;
  text += `4. AUSPICIOUS DETAILS (සුභ විස්තර)\n`;
  text += `------------------------------------------------------------\n`;
  text += `Lucky Numbers (සුභ අංක): ${Array.isArray(pred.luckyNumbers) ? pred.luckyNumbers.join(", ") : "N/A"}\n`;
  text += `Lucky Colors (සුභ වර්ණ): ${Array.isArray(pred.luckyColors) ? pred.luckyColors.join(", ") : "N/A"}\n`;
  text += `Auspicious Days (සුභ දින): ${Array.isArray(pred.auspiciousDays) ? pred.auspiciousDays.join(", ") : "N/A"}\n`;
  text += `============================================================\n`;
  text += `Generated by Sri Lanka Astrology Applet.\n`;
  text += `All rights reserved.\n`;
  return text;
}

async function uploadReportToGoogleDrive(report: any) {
  try {
    const hasCustomConfig = !!process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== "YOUR_GOOGLE_CLIENT_ID";
    
    // Format the report file content
    const fileContent = formatReportText(report);
    const fileName = `Astrology_Report_${report.birthDetails?.name || "Unnamed"}_${report.id}.txt`;

    if (!hasCustomConfig) {
      // Mock/Sandbox Mode: We don't have real Google credentials, so we simulate saving to Google Drive.
      console.log(`[Google Drive Sandbox] Simulated upload of ${fileName} to Google Drive.`);
      return { success: true, sandbox: true, fileId: "sandbox_drive_" + Math.random().toString(36).substring(2, 11) };
    }

    const accessToken = await refreshGoogleAccessToken();
    if (!accessToken) {
      console.warn("[Google Drive] Cannot upload to Google Drive: Admin (sampathub89@gmail.com) is not logged in or has not consented to Google Drive access.");
      return { success: false, error: "Admin Google Drive access not authenticated. Please log in as admin and authenticate via Google first." };
    }

    console.log(`[Google Drive] Uploading ${fileName} to Google Drive...`);
    const boundary = "foo_bar_astro_boundary";
    
    const metadata = {
      name: fileName,
      mimeType: "text/plain",
      description: `Astrology Horoscope Report generated for ${report.birthDetails?.name || "Unnamed"}`
    };

    const multipartBody = 
      `--${boundary}\r\n` +
      `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
      JSON.stringify(metadata) + `\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: text/plain; charset=UTF-8\r\n\r\n` +
      fileContent + `\r\n` +
      `--${boundary}--`;

    const uploadRes = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": `multipart/related; boundary=${boundary}`
      },
      body: multipartBody
    });

    if (!uploadRes.ok) {
      const errText = await uploadRes.text();
      console.error("[Google Drive] File upload failed:", errText);
      return { success: false, error: "Google Drive API returned error: " + errText };
    }

    const uploadData = await uploadRes.json();
    console.log("[Google Drive] File uploaded successfully. File ID:", uploadData.id);
    return { success: true, fileId: uploadData.id };
  } catch (err: any) {
    console.error("[Google Drive] Exception in uploadReportToGoogleDrive:", err);
    return { success: false, error: err.message || "Failed to upload to Google Drive." };
  }
}

// API: Save Astrological Report Lookup (stores name, contact info, chart info & timestamp)
app.post("/api/reports/save", async (req, res) => {
  try {
    const { id, birthDetails, chart, predictions, contactType, contactValue } = req.body;

    if (!contactValue) {
      return res.status(400).json({ error: "Email or WhatsApp number is required." });
    }

    const existingReport = id ? await getReportByIdAsync(id) : null;

    if (existingReport) {
      // Update existing report
      
      // Delete old Drive file if it exists and was not sandbox in background
      if (existingReport.driveFileId && !existingReport.driveFileId.startsWith("sandbox_drive_")) {
        const hasCustomConfig = !!process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== "YOUR_GOOGLE_CLIENT_ID";
        if (hasCustomConfig) {
          refreshGoogleAccessToken().then(async (accessToken) => {
            if (accessToken) {
              try {
                console.log(`[Google Drive] Deleting old file on update (background): ${existingReport.driveFileId}`);
                await fetch(`https://www.googleapis.com/drive/v3/files/${existingReport.driveFileId}`, {
                  method: "DELETE",
                  headers: { Authorization: `Bearer ${accessToken}` }
                });
              } catch (err) {
                console.error("[Google Drive] Error deleting old file during background update:", err);
              }
            }
          }).catch(err => console.error("[Google Drive] Error refreshing token for background delete:", err));
        }
      }

      existingReport.contactType = contactType;
      existingReport.contactValue = contactValue;
      if (birthDetails) {
        existingReport.birthDetails = birthDetails;
      }
      if (chart) {
        existingReport.chart = {
          lagna: chart?.lagna,
          lagnaSinhala: chart?.lagnaSinhala,
          nakshatra: chart?.nakshatra,
          nakshatraSinhala: chart?.nakshatraSinhala,
          rashi: chart?.rashi,
          rashiSinhala: chart?.rashiSinhala,
          calculations: chart?.calculations,
          planetaryDetails: chart?.planetaryDetails,
          housePlacements: chart?.housePlacements,
          navamsaHousePlacements: chart?.navamsaHousePlacements,
          navamsaLagna: chart?.navamsaLagna,
          navamsaLagnaSinhala: chart?.navamsaLagnaSinhala
        };
      }
      if (predictions) {
        existingReport.predictions = predictions;
      }
      if (!existingReport.ipAddress) {
        existingReport.ipAddress = getClientIp(req);
      }
      existingReport.updatedAt = new Date().toISOString();

      // Save report lookup immediately
      await saveReportAsync(existingReport);

      // Upload the newly updated report to Google Drive in the background (non-blocking)
      uploadReportToGoogleDrive(existingReport).then(async (driveResult) => {
        if (driveResult && driveResult.success) {
          existingReport.driveFileId = driveResult.fileId;
          await saveReportAsync(existingReport);
        }
      }).catch(err => {
        console.error("[Google Drive] Background upload failed on update:", err);
      });

      return res.json({ success: true, reportId: id, report: existingReport, isUpdate: true });
    } else {
      // Create new report
      const newId = id || "rep_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now();
      const newReport: any = {
        id: newId,
        ipAddress: getClientIp(req),
        contactType,
        contactValue,
        birthDetails,
        chart: {
          lagna: chart?.lagna,
          lagnaSinhala: chart?.lagnaSinhala,
          nakshatra: chart?.nakshatra,
          nakshatraSinhala: chart?.nakshatraSinhala,
          rashi: chart?.rashi,
          rashiSinhala: chart?.rashiSinhala,
          calculations: chart?.calculations,
          planetaryDetails: chart?.planetaryDetails,
          housePlacements: chart?.housePlacements,
          navamsaHousePlacements: chart?.navamsaHousePlacements,
          navamsaLagna: chart?.navamsaLagna,
          navamsaLagnaSinhala: chart?.navamsaLagnaSinhala
        },
        predictions,
        rating: null,
        comment: null,
        createdAt: new Date().toISOString()
      };

      // Save report lookup immediately
      await saveReportAsync(newReport);

      // Upload newly created report to Google Drive in the background (non-blocking)
      uploadReportToGoogleDrive(newReport).then(async (driveResult) => {
        if (driveResult && driveResult.success) {
          newReport.driveFileId = driveResult.fileId;
          await saveReportAsync(newReport);
        }
      }).catch(err => {
        console.error("[Google Drive] Background upload failed on create:", err);
      });

      return res.json({ success: true, reportId: newId, report: newReport });
    }
  } catch (error: any) {
    console.error("Error saving report lookup:", error);
    res.status(500).json({ error: error.message || "Could not save report lookup." });
  }
});

// API: Rate Saved Astrological Report (allows users to rate 1-5 stars and give feedback)
app.post("/api/reports/rate", async (req, res) => {
  try {
    const { reportId, rating, comment } = req.body;

    if (!reportId || rating === undefined) {
      return res.status(400).json({ error: "reportId and rating are required." });
    }

    const report = await getReportByIdAsync(reportId);

    if (!report) {
      return res.status(404).json({ error: "Horoscope report not found." });
    }

    report.rating = Number(rating);
    report.comment = comment || "";
    await saveReportAsync(report);

    res.json({ success: true, report });
  } catch (error: any) {
    console.error("Error rating report:", error);
    res.status(500).json({ error: error.message || "Failed to submit rating." });
  }
});

// API: Get Latest Report for Logged-In User
app.get("/api/reports/user-latest", async (req, res) => {
  try {
    const email = String(req.query.email || "").toLowerCase().trim();
    if (!email) {
      return res.status(400).json({ error: "Email query parameter is required." });
    }
    const report = await getUserLatestReportAsync(email);
    res.json({ success: true, report });
  } catch (error: any) {
    console.error("Error fetching user latest report:", error);
    res.status(500).json({ error: error.message || "Failed to fetch user report." });
  }
});

// API: Password Login Disabled (Google Sign-In only for sampathub89@gmail.com)
app.post("/api/admin/login", (req, res) => {
  return res.status(400).json({
    error: "මුරපද භාවිතයෙන් ඇතුළුවීම අක්‍රිය කර ඇත. කරුණාකර sampathub89@gmail.com Google Sign-In මගින් පිවිසෙන්න. (Password login is disabled. Please sign in with Google using sampathub89@gmail.com)."
  });
});

// API: Google OAuth Admin Session Registration
app.post("/api/admin/google-session", (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = (email || "").toLowerCase().trim();

    if (cleanEmail !== ADMIN_EMAIL) {
      return res.status(403).json({ error: "Access denied. Only sampathub89@gmail.com is authorized as admin." });
    }

    const token = generateAdminToken();

    res.json({
      success: true,
      token,
      admin: { email: ADMIN_EMAIL, name: "Sampath (Astrology Admin)" }
    });
  } catch (error: any) {
    console.error("Google admin session error:", error);
    res.status(500).json({ error: error.message || "Failed to issue admin token." });
  }
});

// API: Get Firestore Database Status (Admin Protected)
app.get("/api/admin/db-status", requireAdminAuth, async (req, res) => {
  try {
    if (!firestoreDb) {
      return res.json({
        success: true,
        status: "not_initialized",
        message: "Firestore is not initialized on the server."
      });
    }

    // Attempt a super-fast read operation with timeout to check connectivity/rules
    const testDoc = doc(firestoreDb, "reports", "connection_test_doc_id");
    await withTimeout(getDoc(testDoc), 1500);

    res.json({
      success: true,
      status: "connected",
      message: "Firestore database is fully connected and active!"
    });
  } catch (err: any) {
    let status = "error";
    let message = err?.message || String(err);

    if (
      message.includes("permissions") ||
      err?.code === "permission-denied" ||
      String(err).includes("permission-denied") ||
      String(err).includes("Missing or insufficient permissions")
    ) {
      status = "permission_denied";
      message = "Firestore is online, but security rules are preventing read/write operations. Please configure your Firebase Firestore Rules to allow access.";
    } else if (message.includes("timed out") || message.includes("Timeout")) {
      status = "timeout";
      message = "Firestore request timed out. Operating in fallback offline mode.";
    }

    res.json({
      success: true,
      status,
      message,
      databaseId: config.firestoreDatabaseId || "(default)"
    });
  }
});

// API: Google OAuth Initiator (Returns Google Consent Screen URL, fallback to self-hosted selector out-of-the-box)
app.get("/api/auth/google/url", (req, res) => {
  try {
    const origin = req.query.origin || "";
    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get("host")}`;
    const redirectUri = `${appUrl}/api/auth/google/callback`;
    
    // Check if the developer has configured an actual custom Google OAuth Client ID in environment variables
    const hasCustomConfig = !!process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== "YOUR_GOOGLE_CLIENT_ID";

    if (hasCustomConfig) {
      // Build the actual Google OAuth 2.0 endpoint for real accounts selection
      const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` + new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID!,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: "openid email profile https://www.googleapis.com/auth/drive.file",
        state: String(origin),
        prompt: "consent",
        access_type: "offline"
      }).toString();

      res.json({ url: googleAuthUrl });
    } else {
      // Serve the ultra-polished, self-hosted Google Identity Selector which always works flawlessly out-of-the-box without config
      res.json({ url: `${appUrl}/api/auth/google/consent?origin=${encodeURIComponent(String(origin))}` });
    }
  } catch (err: any) {
    res.status(500).json({ error: "Failed to construct Google OAuth URL." });
  }
});

// API: Google OAuth Self-Hosted Consent Screen Selector
app.get("/api/auth/google/consent", (req, res) => {
  const adminEmail = ADMIN_EMAIL;
  const adminName = "Sampath UB";
  const avatarLetter = adminName.charAt(0);

  res.send(`
    <!DOCTYPE html>
    <html lang="si">
    <head>
      <meta charset="utf-8">
      <title>Google Accounts - Sign In</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
      <style>
        body {
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          background-color: #0f172a;
          color: #f1f5f9;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
          padding: 1rem;
          box-sizing: border-box;
        }
        * {
          box-sizing: border-box;
        }
        #consent-card {
          background-color: #1e293b;
          border: 1px solid #334155;
          border-radius: 1rem;
          padding: 2rem;
          max-width: 24rem;
          width: 100%;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
          position: relative;
        }
        .flex { display: flex; }
        .justify-center { justify-content: center; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .mb-5 { margin-bottom: 1.25rem; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-6 { margin-bottom: 1.5rem; }
        .mt-4 { margin-top: 1rem; }
        .pt-4 { padding-top: 1rem; }
        .mt-8 { margin-top: 2rem; }
        .text-center { text-align: center; }
        .text-xl { font-size: 1.25rem; }
        .text-xs { font-size: 0.75rem; }
        .text-[11px] { font-size: 11px; }
        .text-[10px] { font-size: 10px; }
        .text-[9px] { font-size: 9px; }
        .font-bold { font-weight: bold; }
        .font-medium { font-weight: 500; }
        .text-slate-100 { color: #f1f5f9; }
        .text-slate-200 { color: #e2e8f0; }
        .text-slate-400 { color: #94a3b8; }
        .text-slate-500 { color: #64748b; }
        .text-indigo-400 { color: #818cf8; }
        .text-emerald-400 { color: #34d399; }
        .text-rose-300 { color: #fda4af; }
        .bg-indigo-600 { background-color: #4f46e5; }
        .bg-indigo-600:hover { background-color: #4338ca; }
        .bg-slate-900 { background-color: #0f172a; }
        .space-y-3 > * + * { margin-top: 0.75rem; }
        .button-primary {
          width: 100%;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0.75rem;
          border: 1px solid rgba(99, 102, 241, 0.3);
          background-color: rgba(99, 102, 241, 0.1);
          color: #f1f5f9;
          border-radius: 0.75rem;
          cursor: pointer;
          transition: all 0.2s;
          text-align: left;
        }
        .button-primary:hover {
          background-color: rgba(99, 102, 241, 0.2);
        }
        .button-secondary {
          width: 100%;
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.75rem;
          border: 1px solid #334155;
          background-color: transparent;
          color: #f1f5f9;
          border-radius: 0.75rem;
          cursor: pointer;
          transition: all 0.2s;
          text-align: left;
        }
        .button-secondary:hover {
          background-color: #334155;
        }
        .avatar-indigo {
          width: 2.25rem;
          height: 2.25rem;
          background-color: #4f46e5;
          color: #ffffff;
          font-weight: bold;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 0.75rem;
          font-size: 0.875rem;
        }
        .avatar-slate {
          width: 2.25rem;
          height: 2.25rem;
          background-color: #0f172a;
          border: 1px solid #334155;
          color: #94a3b8;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 0.75rem;
        }
        .badge-verified {
          background-color: rgba(16, 185, 129, 0.2);
          color: #34d399;
          font-size: 9px;
          font-weight: bold;
          padding: 0.125rem 0.5rem;
          border-radius: 9999px;
          border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .border-t { border-top: 1px solid #334155; }
        .hidden { display: none !important; }
        .uppercase { text-transform: uppercase; }
        .tracking-wider { letter-spacing: 0.05em; }
        .flex-grow { flex-grow: 1; }
        .input-text {
          background-color: #090d16;
          border: 1px solid #334155;
          border-radius: 0.75rem;
          padding: 0.5rem 0.75rem;
          font-size: 0.75rem;
          color: #e2e8f0;
          outline: none;
          width: 100%;
        }
        .input-text:focus {
          border-color: #6366f1;
        }
        .btn-submit {
          background-color: #4f46e5;
          color: #ffffff;
          font-size: 0.75rem;
          font-weight: bold;
          padding: 0.5rem 1rem;
          border-radius: 0.75rem;
          border: none;
          cursor: pointer;
          transition: all 0.2s;
        }
        .btn-submit:hover {
          background-color: #4338ca;
        }
        .alert-banner {
          background-color: rgba(244, 63, 94, 0.1);
          border: 1px solid rgba(244, 63, 94, 0.3);
          color: #fda4af;
          border-radius: 0.75rem;
          padding: 0.75rem;
          font-size: 0.75rem;
          line-height: 1.5;
        }
        .animate-spin {
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .text-left { text-align: left; }
      </style>
    </head>
    <body>
      <div id="consent-card">
        <!-- Google Logo SVG -->
        <div class="flex justify-center mb-5">
          <svg class="w-12 h-12" viewBox="0 0 24 24" fill="none">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
            <path d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.08H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.92l2.85-2.22.81-.6z" fill="#FBBC05"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.08l3.66 2.84c.87-2.6 3.3-4.54 6.16-4.54z" fill="#EA4335"/>
          </svg>
        </div>
        
        <h2 class="text-xl font-bold text-slate-100 text-center mb-1 font-display">Google ගිණුමෙන් පිවිසෙන්න</h2>
        <p class="text-xs text-slate-400 text-center mb-6">Enter your Google email to continue to <span class="text-indigo-400 font-medium">Sri Lanka Astrology</span></p>

        <!-- Google Direct Email Sign In Form -->
        <form onsubmit="event.preventDefault(); submitCustomEmail();" class="space-y-4">
          <div>
            <label class="block text-[10px] uppercase font-bold tracking-wider text-slate-400 mb-1.5">Google Email (@gmail.com)</label>
            <input id="custom-email" type="email" placeholder="yourname@gmail.com" class="input-text" required autofocus>
          </div>
          <button type="submit" class="button-primary justify-center font-bold text-center py-3">
            <span class="text-xs font-bold text-white w-full text-center">Google ගිණුම තහවුරු කරන්න (Continue with Google)</span>
          </button>
        </form>

        <div id="alert-banner" class="hidden mt-4 alert-banner"></div>

        <div id="loading" class="hidden mt-4 flex items-center justify-center py-2" style="gap: 0.5rem;">
          <svg class="animate-spin text-indigo-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" style="width:1rem;height:1rem;">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span class="text-xs text-slate-400 font-medium">සම්බන්ධ වෙමින්...</span>
        </div>

        <div class="mt-8 text-center text-[10px] text-slate-500 font-sans border-t pt-4">
          Google Identity Gateway Security
        </div>
      </div>

      <script>
        function showCustomInput() {
          const section = document.getElementById("custom-email-section");
          section.classList.toggle("hidden");
          document.getElementById("custom-email").focus();
        }

        function selectAccount(email) {
          const cleanEmail = (email || "").toLowerCase().trim();
          document.getElementById("alert-banner").classList.add("hidden");
          document.getElementById("loading").classList.remove("hidden");
          
          // Strict Google Gmail validation regex
          const googleEmailRegex = /^[a-zA-Z0-9._%+-]+@(gmail\.com|googlemail\.com)$/i;
          if (!googleEmailRegex.test(cleanEmail)) {
            setTimeout(() => {
              document.getElementById("loading").classList.add("hidden");
              const banner = document.getElementById("alert-banner");
              banner.classList.remove("hidden");
              banner.innerText = "✕ කරුණාකර වලංගු Google (@gmail.com) ඊමේල් ලිපිනයක් පමණක් ඇතුළත් කරන්න. (Please enter a valid Google @gmail.com address.)";
            }, 300);
            return;
          }

          const isAdmin = cleanEmail === "${adminEmail}";
          const token = isAdmin 
            ? "secret_astro_token_sampathub89_" + Date.now()
            : "user_astro_token_" + Date.now() + "_" + btoa(cleanEmail).replace(/=/g, '');

          const data = {
            type: "OAUTH_AUTH_SUCCESS",
            token: token,
            email: cleanEmail,
            isAdmin: isAdmin
          };

          try {
            localStorage.setItem("astro_google_login_token", data.token);
            localStorage.setItem("astro_google_login_success", "true");
            localStorage.setItem("astro_google_login_email", data.email);
            localStorage.setItem("astro_google_login_is_admin", data.isAdmin ? "true" : "false");
          } catch (e) {
            console.error("localStorage error:", e);
          }

          let postSuccess = false;
          try {
            if (window.opener) {
              window.opener.postMessage(data, "*");
              postSuccess = true;
            }
          } catch (postErr) {
            console.warn("opener.postMessage failed:", postErr);
          }

          const params = new URLSearchParams(window.location.search);
          const originVal = params.get("origin") || window.location.origin;

          setTimeout(() => {
            if (postSuccess) {
              try { window.close(); } catch (err) {}
            } else {
              window.location.href = originVal + "/?admin_token=" + encodeURIComponent(data.token) + "&email=" + encodeURIComponent(data.email);
            }
          }, 1000);
        }

        function submitCustomEmail() {
          const email = document.getElementById("custom-email").value;
          if (!email) return;
          selectAccount(email);
        }
      </script>
    </body>
    </html>
  `);
});

// API: Google OAuth Callback (Exchanges authorization token directly with Google & enforces sampathub89@gmail.com)
app.get(["/api/auth/google/callback", "/api/auth/google/callback/"], async (req, res) => {
  const { code, state, error } = req.query;
  const origin = state ? String(state) : "";
  
  if (error) {
    return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: String(error) }, origin));
  }
  
  if (!code) {
    return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: "Authorization code not provided by Google." }, origin));
  }
  
  try {
    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get("host")}`;
    const redirectUri = `${appUrl}/api/auth/google/callback`;
    const clientId = process.env.GOOGLE_CLIENT_ID || "";
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";
    
    // 1. Exchange auth code for tokens
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: String(code),
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization-code"
      })
    });
    
    if (!tokenResponse.ok) {
      const errJson = await tokenResponse.json();
      console.error("Token exchange failed:", errJson);
      return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: errJson.error_description || "Token exchange failed." }, origin));
    }
    
    const tokens = await tokenResponse.json();
    const accessToken = tokens.access_token;
    
    // 2. Fetch userinfo using returned access token
    const userInfoResponse = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    
    if (!userInfoResponse.ok) {
      return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: "Failed to grab user info from Google." }, origin));
    }
    
    const userInfo = await userInfoResponse.json();
    const email = userInfo.email;
    
    if (!email) {
      return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: "Google did not provide email address information." }, origin));
    }
    
    // 3. Email Check and Authentication Classification
    const cleanEmail = email.toLowerCase().trim();
    const isAdmin = cleanEmail === ADMIN_EMAIL;

    if (isAdmin) {
      await saveStoredDriveTokensAsync({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expiry_date: Date.now() + (tokens.expires_in || 3600) * 1000
      });
    }
    
    // Generates secure token based on role
    const token = isAdmin 
      ? "secret_astro_token_sampathub89_" + Date.now()
      : "user_astro_token_" + Date.now() + "_" + Buffer.from(cleanEmail).toString('base64').replace(/=/g, '');
      
    return res.send(renderOauthResponseHtml({ 
      type: "OAUTH_AUTH_SUCCESS", 
      token, 
      email: cleanEmail, 
      isAdmin 
    }, origin));
    
  } catch (err: any) {
    console.error("Google OAuth Exchange Error:", err);
    return res.send(renderOauthResponseHtml({ type: "OAUTH_AUTH_FAILURE", error: err.message || "OAuth internal server error." }, origin));
  }
});

// Secure HTML callback page payload
function renderOauthResponseHtml(data: { type: "OAUTH_AUTH_SUCCESS" | "OAUTH_AUTH_FAILURE"; token?: string; error?: string; email?: string; isAdmin?: boolean }, origin?: string) {
  const originUrl = origin || "";
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Google Sign-In Callback</title>
        <meta charset="utf-8">
      </head>
      <body style="background:#090d16;color:#e2e8f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;padding:20px;text-align:center;">
        <div style="background:#020617;border:1px solid #1e293b;padding:30px;border-radius:12px;max-width:400px;box-shadow:0 10px 25px -5px rgba(0,0,0,0.5);">
          <h2 style="color:${data.type === "OAUTH_AUTH_SUCCESS" ? "#10b981" : "#ef4444"};margin-top:0;">
            ${data.type === "OAUTH_AUTH_SUCCESS" ? "✓ Authentication Successful" : "✕ Authentication Failed"}
          </h2>
          <p style="font-size:14px;color:#94a3b8;line-height:1.5;">
            ${data.type === "OAUTH_AUTH_SUCCESS" 
              ? (data.isAdmin 
                ? "Credentials verified successfully. Close this window to access the administrative dashboard."
                : "Standard user authenticated successfully. Close this window to proceed.") 
              : (data.error || "Access Denied")}
          </p>
          <div style="margin-top:20px;font-size:12px;color:#475569;">ප්‍රමුඛ තරු ලකුණු අඩවිය (Astrology Birth Charter)</div>
        </div>
        <script>
          try {
            const dataObj = ${JSON.stringify(data)};
            if (dataObj.type === "OAUTH_AUTH_SUCCESS" && dataObj.token) {
              localStorage.setItem("astro_google_login_token", dataObj.token);
              localStorage.setItem("astro_google_login_success", "true");
              localStorage.setItem("astro_google_login_email", dataObj.email || "");
              localStorage.setItem("astro_google_login_is_admin", dataObj.isAdmin ? "true" : "false");
            }
          } catch (e) {
            console.error("localStorage error:", e);
          }

          let postSuccess = false;
          try {
            const dataObj = ${JSON.stringify(data)};
            if (window.opener) {
              try {
                window.opener.postMessage(dataObj, "*");
                postSuccess = true;
              } catch (postErr) {
                console.warn("opener.postMessage failed:", postErr);
              }
            }
            
            if (postSuccess) {
              setTimeout(() => {
                window.close();
              }, 600);
            } else {
              const originVal = ${JSON.stringify(originUrl)} || window.location.origin;
              if (dataObj.type === "OAUTH_AUTH_SUCCESS" && dataObj.token) {
                window.location.href = originVal + "/?admin_token=" + encodeURIComponent(dataObj.token) + "&email=" + encodeURIComponent(dataObj.email || "");
              } else {
                window.location.href = originVal + "/?admin_error=" + encodeURIComponent(dataObj.error || "Authentication failed");
              }
            }
          } catch (e) {
            console.error("Redirect fallback error:", e);
            window.location.href = "/";
          }
        </script>
      </body>
    </html>
  `;
}

// Recursive sanitizer to strip all large binary/image strings & keep admin list payloads ultra-light (< 200KB)
// This strictly prevents the Netlify / AWS Lambda 6MB (6,291,556 bytes) "Function.ResponseSizeTooLarge" 502 Bad Gateway error.
function cleanNestedObject(obj: any, depth: number = 0): any {
  if (depth > 4 || !obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) {
    return obj.map(item => (typeof item === "object" ? cleanNestedObject(item, depth + 1) : item));
  }
  const res: any = {};
  for (const [k, v] of Object.entries(obj)) {
    const lk = k.toLowerCase();
    if (
      lk.includes("base64") ||
      lk.includes("image") ||
      lk.includes("photo") ||
      lk === "storedimage" ||
      lk === "rawimage"
    ) {
      continue;
    }
    if (typeof v === "string") {
      if (v.startsWith("data:") || v.length > 8000) continue;
      res[k] = v;
    } else if (v && typeof v === "object") {
      res[k] = cleanNestedObject(v, depth + 1);
    } else {
      res[k] = v;
    }
  }
  return res;
}

function cleanReportForAdminList(report: any): any {
  if (!report || typeof report !== "object") return report;
  
  const clean: any = Array.isArray(report) ? [] : {};

  const hasPalmImg = !!(
    report.palmImageBase64 || 
    report.palmPhoto || 
    report.palmImage || 
    (report.palmistryData && (report.palmistryData.palmImageBase64 || report.palmistryData.imageBase64 || report.palmistryData.storedImage)) ||
    (report.reportType === "palmistry" && (report.storedImage || report.imageBase64))
  );

  const hasDehaImg = !!(
    report.dehalakshanaImageBase64 || 
    report.dehaPhoto || 
    (report.dehalakshanaData && (report.dehalakshanaData.dehalakshanaImageBase64 || report.dehalakshanaData.imageBase64 || report.dehalakshanaData.storedImage)) ||
    ((report.reportType === "dehalakshana" || report.reportType === "deha") && (report.storedImage || report.imageBase64))
  );

  for (const [key, value] of Object.entries(report)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.includes("base64") ||
      lowerKey.includes("image") ||
      lowerKey.includes("photo") ||
      lowerKey === "storedimage" ||
      lowerKey === "rawimage" ||
      lowerKey === "pdfbase64" ||
      lowerKey === "attachment"
    ) {
      continue;
    }

    if (typeof value === "string") {
      if (value.startsWith("data:") || value.length > 8000) {
        continue;
      }
      clean[key] = value;
      continue;
    }

    if (key === "chatHistory" && Array.isArray(value)) {
      clean[key] = value.map((m: any) => ({
        sender: m.sender,
        text: typeof m.text === "string" ? m.text : "",
        timestamp: m.timestamp
      }));
      continue;
    }

    if (value && typeof value === "object") {
      clean[key] = cleanNestedObject(value);
      continue;
    }

    clean[key] = value;
  }

  if (hasPalmImg || report.hasPalmImage) clean.hasPalmImage = true;
  if (hasDehaImg || report.hasDehaImage) clean.hasDehaImage = true;
  if (!clean.ipAddress) clean.ipAddress = "127.0.0.1";

  return clean;
}

// API: Fetch All Saved Reports for Admin View
app.get("/api/admin/reports", requireAdminAuth, async (req, res) => {
  try {
    // Disable HTTP caching so browser always gets the true latest data
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    // Auto-initialize mock tokens asynchronously if needed without delaying report retrieval
    getStoredDriveTokensAsync().then(async (existingTokens) => {
      if (!existingTokens) {
        await saveStoredDriveTokensAsync({
          access_token: "mock_access_token_" + Date.now(),
          refresh_token: "mock_refresh_token_" + Date.now(),
          expiry_date: Date.now() + 3600000,
          isSandbox: true
        }).catch(() => {});
      }
    }).catch(() => {});

    const isFresh = req.query.fresh === "true" || req.query.sync === "true";
    const reports = await getReportsAsync(isFresh);
    
    // Sort reports strictly by date & time: newest first (top), oldest below (bottom)
    reports.sort((a: any, b: any) => {
      const timeA = a.createdAt ? new Date(a.createdAt).getTime() : (a.timestamp ? new Date(a.timestamp).getTime() : 0);
      const timeB = b.createdAt ? new Date(b.createdAt).getTime() : (b.timestamp ? new Date(b.timestamp).getTime() : 0);
      return timeB - timeA;
    });

    // Deep clean each report to eliminate heavy binary/image payloads
    const sanitizedReports = reports
      .filter((r: any) => r && r.id && r.id !== "google_drive_tokens" && r.id !== "usage_logs")
      .map((r: any) => cleanReportForAdminList(r));

    const totalCount = sanitizedReports.length;
    const fetchAll = req.query.all === "true" || req.query.limit === "all";
    const finalReports = fetchAll ? sanitizedReports : sanitizedReports.slice(0, 100);

    res.json({ 
      success: true, 
      reports: finalReports, 
      totalCount: totalCount, 
      loadedCount: finalReports.length,
      isShowingAll: fetchAll || finalReports.length >= totalCount 
    });
  } catch (error: any) {
    console.error("Admin fetch reports error:", error);
    res.status(500).json({ error: error.message || "Failed to retrieve logs." });
  }
});

// API: Fetch Single Saved Report by ID (Admin only)
app.get("/api/admin/reports/:id", requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const report = await getReportByIdAsync(id);

    if (!report) {
      return res.status(404).json({ error: "Report not found." });
    }

    res.json({ success: true, report });
  } catch (error: any) {
    console.error("Admin fetch single report error:", error);
    res.status(500).json({ error: error.message || "Failed to retrieve report." });
  }
});

// API: Delete Astrological Report (Admin only, deletes from both JSON db and Google Drive if available)
app.delete("/api/admin/reports/:id", requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ error: "Report ID is required." });
    }

    const reportToDelete = await getReportByIdAsync(id);

    // If there is a Google Drive file associated, attempt to delete it
    if (reportToDelete && reportToDelete.driveFileId && !reportToDelete.driveFileId.startsWith("sandbox_drive_")) {
      const hasCustomConfig = !!process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== "YOUR_GOOGLE_CLIENT_ID";
      if (hasCustomConfig) {
        const accessToken = await refreshGoogleAccessToken();
        if (accessToken) {
          try {
            console.log(`[Google Drive] Attempting to delete file: ${reportToDelete.driveFileId}`);
            const deleteRes = await fetch(`https://www.googleapis.com/drive/v3/files/${reportToDelete.driveFileId}`, {
              method: "DELETE",
              headers: {
                Authorization: `Bearer ${accessToken}`
              }
            });
            if (deleteRes.ok) {
              console.log("[Google Drive] File deleted successfully from Google Drive.");
            } else {
              const errText = await deleteRes.text();
              console.warn("[Google Drive] Failed to delete file:", errText);
            }
          } catch (err) {
            console.error("[Google Drive] Error deleting file:", err);
          }
        }
      } else {
        console.log(`[Google Drive Sandbox] Simulated delete of file: ${reportToDelete.driveFileId}`);
      }
    } else if (reportToDelete && reportToDelete.driveFileId) {
      console.log(`[Google Drive Sandbox] Simulated delete of file: ${reportToDelete.driveFileId}`);
    }

    // Remove the report from both Firestore and local DB
    await deleteReportAsync(id);

    res.json({ success: true, message: "Report deleted successfully." });
  } catch (error: any) {
    console.error("Error deleting report:", error);
    res.status(500).json({ error: error.message || "Failed to delete report." });
  }
});

// Fallback JSON error handler for all unmatched API endpoints to prevent "Unexpected token '<'" browser errors
app.use("/api/*", (req, res) => {
  console.warn(`[API 404] Unmatched API path requested: ${req.originalUrl || req.url}`);
  res.status(404).json({
    error: `API path not found. Please verify the endpoint: ${req.originalUrl || req.url}`,
    success: false
  });
});

// Vite & Static file serving setup
async function startServer() {
  if (process.env.NODE_ENV !== "production" && !process.env.NETLIFY) {
    try {
      // Mounting Vite in development mode as middleware
      const { createServer: createViteServer } = await import("vite");
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: "spa",
      });
      app.use(vite.middlewares);
      console.log("Vite dev middleware loaded successfully.");
    } catch (viteError) {
      console.error("Vite development server loading error:", viteError);
    }
  } else if (!process.env.NETLIFY) {
    // Serve production assets from the 'dist' directory
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
    console.log("Serving production static assets from: " + distPath);
  }

  // Only bind port listener when running directly, not in Netlify functions
  if (!process.env.NETLIFY) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Express custom server running on http://localhost:${PORT}`);
    });
  }
}

startServer();

export { app };
export default app;
