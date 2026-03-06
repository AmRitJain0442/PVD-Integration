const URL_SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "is.gd",
  "rb.gy",
  "rebrand.ly",
  "ow.ly",
]);

const HIGH_RISK_TLDS = new Set([
  "zip",
  "click",
  "work",
  "gq",
  "top",
  "country",
  "kim",
  "fit",
]);

const LURE_KEYWORDS = [
  "login",
  "verify",
  "account",
  "wallet",
  "secure",
  "update",
  "bank",
  "auth",
  "gift",
  "support",
];

export async function runPermissionAudit(engine) {
  const permissionNames = [
    "camera",
    "microphone",
    "geolocation",
    "notifications",
    "clipboard-read",
    "bluetooth",
  ];

  const states = {};
  for (const name of permissionNames) {
    const result = await queryPermissionState(name);
    states[name] = result.state;
    if (result.state === "denied") {
      engine.addFinding({
        source: "permission-audit",
        title: `${name} permission is denied`,
        detail:
          "Blocked permission can break security telemetry collection. Confirm user intent and policy defaults.",
        severity: "medium",
        confidence: 0.85,
      });
    } else if (result.state === "prompt") {
      engine.addFinding({
        source: "permission-audit",
        title: `${name} permission pending`,
        detail:
          "Permission is not granted yet. Capture this state to avoid blind spots in risk telemetry.",
        severity: "low",
        confidence: 0.6,
      });
    }
  }

  if (!("permissions" in navigator)) {
    engine.addFinding({
      source: "permission-audit",
      title: "Permissions API unavailable",
      detail: "Browser cannot fully audit permission posture using standard APIs.",
      severity: "low",
      confidence: 0.65,
    });
  }

  engine.setSignal("permissions", states);
}

export async function runDeviceSurfaceAudit(engine) {
  const surface = {
    userAgent: navigator.userAgent,
    platform: navigator.platform || "unknown",
    language: navigator.language || "unknown",
    cookieEnabled: navigator.cookieEnabled,
    online: navigator.onLine,
    hardwareConcurrency: navigator.hardwareConcurrency || "n/a",
    deviceMemoryGb: navigator.deviceMemory || "n/a",
    secureContext: window.isSecureContext,
  };

  if (!window.isSecureContext && location.hostname !== "localhost") {
    engine.addFinding({
      source: "device-surface",
      title: "Application running outside secure context",
      detail: "Production usage should run over HTTPS to protect browser APIs and session integrity.",
      severity: "high",
      confidence: 0.9,
    });
  }

  if (/Trident|MSIE/i.test(navigator.userAgent)) {
    engine.addFinding({
      source: "device-surface",
      title: "Legacy browser signature detected",
      detail:
        "Legacy engines can miss modern security controls. Enforce browser version policy for sensitive workflows.",
      severity: "high",
      confidence: 0.88,
    });
  }

  if (!navigator.cookieEnabled) {
    engine.addFinding({
      source: "device-surface",
      title: "Cookies disabled",
      detail:
        "Cookie-disabled environments can break secure auth/session flows; verify fallback auth strategy.",
      severity: "low",
      confidence: 0.6,
    });
  }

  engine.setSignal("deviceSurface", surface);
}

export async function runNetworkSignalAudit(engine) {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  const network = {
    online: navigator.onLine,
    protocol: location.protocol,
    host: location.host,
    effectiveType: connection?.effectiveType || "unknown",
    downlinkMbps: connection?.downlink ?? "unknown",
    rttMs: connection?.rtt ?? "unknown",
    saveData: Boolean(connection?.saveData),
    localIps: [],
  };

  if (location.protocol !== "https:" && location.hostname !== "localhost") {
    engine.addFinding({
      source: "network-signals",
      title: "Insecure transport protocol detected",
      detail: "Non-HTTPS traffic enables interception and metadata leakage.",
      severity: "high",
      confidence: 0.93,
    });
  }

  if (!navigator.onLine) {
    engine.addFinding({
      source: "network-signals",
      title: "Device reports offline mode",
      detail: "Offline mode can delay telemetry and block active response actions.",
      severity: "medium",
      confidence: 0.76,
    });
  }

  if (connection?.effectiveType === "2g") {
    engine.addFinding({
      source: "network-signals",
      title: "Low-bandwidth link detected",
      detail: "Constrained network conditions can degrade incident data upload reliability.",
      severity: "low",
      confidence: 0.58,
    });
  }

  network.localIps = await discoverLocalIps();
  if (network.localIps.length > 0) {
    engine.addFinding({
      source: "network-signals",
      title: "Local network interfaces discovered",
      detail: `Detected local IP candidates: ${network.localIps.join(", ")}. Use this for controlled network-segmentation checks.`,
      severity: "info",
      confidence: 0.5,
    });
  }

  engine.setSignal("networkSignals", network);
}

export async function runBluetoothAudit(engine) {
  const supported = "bluetooth" in navigator;
  engine.setSignal("bluetooth", {
    supported,
    secureContext: window.isSecureContext,
  });

  if (!supported) {
    engine.addFinding({
      source: "bluetooth",
      title: "Web Bluetooth is unavailable in this browser",
      detail:
        "If your product requires BLE telemetry, document browser compatibility and fallback integrations.",
      severity: "low",
      confidence: 0.74,
    });
    return;
  }

  if (!window.isSecureContext) {
    engine.addFinding({
      source: "bluetooth",
      title: "Bluetooth APIs blocked by insecure context",
      detail: "BLE-based detection flows require HTTPS.",
      severity: "medium",
      confidence: 0.85,
    });
  }
}

export function analyzeUrlHeuristics(engine, rawInput) {
  const trimmed = String(rawInput || "").trim();
  if (!trimmed) {
    engine.addFinding({
      source: "url-triage",
      title: "No URL provided for triage",
      detail: "Add a URL to run phishing and deception heuristics.",
      severity: "low",
      confidence: 0.95,
    });
    return;
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    engine.addFinding({
      source: "url-triage",
      title: "Invalid URL format",
      detail: `Could not parse input: ${trimmed}`,
      severity: "medium",
      confidence: 0.95,
    });
    return;
  }

  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split(".");
  const tld = labels[labels.length - 1] || "";

  if (parsed.protocol !== "https:") {
    engine.addFinding({
      source: "url-triage",
      title: "Non-HTTPS URL detected",
      detail: `${parsed.href} does not use HTTPS.`,
      severity: "high",
      confidence: 0.9,
    });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    engine.addFinding({
      source: "url-triage",
      title: "Direct IP host in URL",
      detail: "Phishing kits commonly use direct IP addresses to bypass domain controls.",
      severity: "high",
      confidence: 0.88,
    });
  }

  if (hostname.includes("xn--")) {
    engine.addFinding({
      source: "url-triage",
      title: "Potential punycode homograph domain",
      detail: "IDN/punycode patterns can be used for lookalike phishing domains.",
      severity: "high",
      confidence: 0.84,
    });
  }

  if (URL_SHORTENER_DOMAINS.has(hostname)) {
    engine.addFinding({
      source: "url-triage",
      title: "URL shortener detected",
      detail: "Shortened URLs hide final destination and increase user deception risk.",
      severity: "medium",
      confidence: 0.78,
    });
  }

  if (HIGH_RISK_TLDS.has(tld)) {
    engine.addFinding({
      source: "url-triage",
      title: `High-risk TLD observed (.${tld})`,
      detail: "This TLD appears frequently in low-reputation campaigns.",
      severity: "medium",
      confidence: 0.67,
    });
  }

  if (parsed.href.length > 120) {
    engine.addFinding({
      source: "url-triage",
      title: "Excessively long URL",
      detail: "Long URLs can conceal malicious parameters and fake path structures.",
      severity: "medium",
      confidence: 0.72,
    });
  }

  if (labels.length >= 5) {
    engine.addFinding({
      source: "url-triage",
      title: "Deep subdomain chain",
      detail: "Abnormally deep hostnames are common in spoofed infrastructure.",
      severity: "medium",
      confidence: 0.73,
    });
  }

  const lower = parsed.href.toLowerCase();
  const keywordHits = LURE_KEYWORDS.filter((word) => lower.includes(word));
  if (keywordHits.length >= 2) {
    engine.addFinding({
      source: "url-triage",
      title: "Credential-lure wording detected",
      detail: `Keywords observed: ${keywordHits.join(", ")}`,
      severity: "high",
      confidence: 0.81,
    });
  }

  engine.setSignal("lastUrlTriage", {
    input: trimmed,
    analyzedAt: new Date().toISOString(),
    keywordHits,
  });
}

async function queryPermissionState(name) {
  if (!navigator.permissions || !navigator.permissions.query) {
    return { name, state: "unsupported" };
  }
  try {
    const status = await navigator.permissions.query({ name });
    return { name, state: status.state };
  } catch {
    return { name, state: "unsupported" };
  }
}

async function discoverLocalIps(timeoutMs = 1300) {
  if (!window.RTCPeerConnection) {
    return [];
  }
  return new Promise((resolve) => {
    const ips = new Set();
    const peer = new RTCPeerConnection({ iceServers: [] });
    peer.createDataChannel("probe");

    peer.onicecandidate = (event) => {
      const candidate = event?.candidate?.candidate || "";
      const matches = candidate.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g);
      if (matches) {
        for (const match of matches) {
          if (isPrivateIp(match)) {
            ips.add(match);
          }
        }
      }
    };

    peer
      .createOffer()
      .then((offer) => peer.setLocalDescription(offer))
      .catch(() => {
        resolve([]);
      });

    setTimeout(() => {
      peer.close();
      resolve(Array.from(ips));
    }, timeoutMs);
  });
}

function isPrivateIp(ip) {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

