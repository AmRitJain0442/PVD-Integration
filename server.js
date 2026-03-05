const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL } = require("url");

const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const PORT = Number(process.env.PORT || 3000);
const BODY_LIMIT = 2 * 1024 * 1024;
const eventStore = [];

loadEnvFile(path.join(ROOT_DIR, ".env"));

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".svg": "image/svg+xml; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};

const server = http.createServer(async (req, res) => {
  try {
    const baseUrl = `http://${req.headers.host || "localhost"}`;
    const requestUrl = new URL(req.url || "/", baseUrl);
    const pathname = requestUrl.pathname;

    if (pathname.startsWith("/api/")) {
      await handleApi(req, res, pathname);
      return;
    }

    await serveStatic(req, res, pathname);
  } catch (error) {
    sendJson(res, 500, {
      error: "Unhandled server error",
      detail: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

server.listen(PORT, () => {
  console.log(`NightWatch Sentinel running on http://localhost:${PORT}`);
});

async function handleApi(req, res, pathname) {
  if (req.method === "OPTIONS") {
    sendEmpty(res, 204);
    return;
  }

  if (req.method === "GET" && pathname === "/api/health") {
    sendJson(res, 200, {
      status: "ok",
      uptimeSec: Number(process.uptime().toFixed(2)),
      now: new Date().toISOString(),
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
    });
    return;
  }

  if (req.method === "GET" && pathname === "/api/events") {
    sendJson(res, 200, {
      count: eventStore.length,
      items: eventStore.slice(-100),
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/events/ingest") {
    const body = await parseJsonBody(req);
    const entry = {
      id: String(Date.now()),
      source: body?.source || "nightwatch-ui",
      receivedAt: new Date().toISOString(),
      payload: body,
    };
    eventStore.push(entry);
    sendJson(res, 200, { status: "stored", id: entry.id, total: eventStore.length });
    return;
  }

  if (req.method === "POST" && pathname === "/api/gemini/analyze") {
    const body = await parseJsonBody(req);
    const context = body?.context || {};
    const userGoal = body?.userGoal || "Create a security remediation plan.";
    const result = await generateGeminiPlan(context, userGoal);
    sendJson(res, 200, result);
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
}

async function serveStatic(req, res, requestPath) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  const safePath = requestPath === "/" ? "/index.html" : requestPath;
  const candidates = buildStaticCandidates(safePath);

  for (const candidate of candidates) {
    const normalized = path.normalize(candidate).replace(/^(\.\.[/\\])+/, "");
    const filePath = path.join(PUBLIC_DIR, normalized);

    if (!filePath.startsWith(PUBLIC_DIR)) {
      sendJson(res, 403, { error: "Forbidden path" });
      return;
    }

    try {
      const stat = await fs.promises.stat(filePath);
      if (stat.isDirectory()) {
        continue;
      }
      const ext = path.extname(filePath).toLowerCase();
      const mimeType = MIME_TYPES[ext] || "application/octet-stream";
      const content = await fs.promises.readFile(filePath);
      res.writeHead(200, {
        "Content-Type": mimeType,
        "Content-Length": content.length,
        "Cache-Control": "no-store",
      });
      res.end(req.method === "HEAD" ? undefined : content);
      return;
    } catch {
      continue;
    }
  }

  sendJson(res, 404, { error: "File not found" });
}

async function generateGeminiPlan(context, userGoal) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    return {
      ok: false,
      message: "Missing GEMINI_API_KEY. Add it to .env to enable AI incident playbooks.",
      text: "Gemini key is not configured. Add GEMINI_API_KEY in .env and retry.",
    };
  }

  const prompt = [
    "You are a senior SOC architect and cyber incident commander.",
    "Given the scan context, output a practical action plan with the following sections:",
    "1) Immediate containment actions (0-4 hours)",
    "2) Hardening actions (24-72 hours)",
    "3) Product roadmap recommendations (hackathon MVP -> startup scale)",
    "4) Integrations to SIEM/SOAR and API-first feature modules",
    "5) Risk justification in business language",
    "",
    `Goal: ${userGoal}`,
    "",
    "Scan context JSON:",
    JSON.stringify(context, null, 2),
  ].join("\n");

  const endpoint =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

  const response = await fetch(`${endpoint}?key=${encodeURIComponent(key)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.25,
        topP: 0.9,
        maxOutputTokens: 1300,
      },
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    return {
      ok: false,
      message: "Gemini API request failed",
      status: response.status,
      text: errorText.slice(0, 500),
    };
  }

  const data = await response.json();
  const text =
    data?.candidates?.[0]?.content?.parts?.map((part) => part?.text || "").join("\n").trim() ||
    "No response text returned by Gemini.";

  return {
    ok: true,
    model: "gemini-2.0-flash",
    createdAt: new Date().toISOString(),
    text,
  };
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const equalIndex = trimmed.indexOf("=");
    if (equalIndex === -1) {
      continue;
    }
    const key = trimmed.slice(0, equalIndex).trim();
    const rawValue = trimmed.slice(equalIndex + 1).trim();
    const value = rawValue.replace(/^["']|["']$/g, "");
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function buildStaticCandidates(requestPath) {
  if (path.extname(requestPath)) {
    return [requestPath];
  }

  return [requestPath, `${requestPath}.html`, path.join(requestPath, "index.html")];
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > BODY_LIMIT) {
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload) {
  const data = Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": data.length,
    "Cache-Control": "no-store",
  });
  res.end(data);
}

function sendEmpty(res, statusCode) {
  res.writeHead(statusCode, {
    "Cache-Control": "no-store",
  });
  res.end();
}

