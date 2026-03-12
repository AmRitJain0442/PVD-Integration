import { RiskEngine } from "./modules/riskEngine.js";
import {
  analyzeUrlHeuristics,
  runBluetoothAudit,
  runDeviceSurfaceAudit,
  runNetworkSignalAudit,
  runPermissionAudit,
} from "./modules/analyzers.js";

const DEFAULT_GOAL = "Prioritize immediate containment and a 72-hour hardening roadmap.";
const POLL_INTERVAL_MS = 15000;

const SCENARIOS = {
  "phishing-kit": {
    title: "Phishing Kit",
    goal: "Create a 24-hour containment plan for the phishing infrastructure and user notification workflow.",
    signals: {
      lastUrlTriage: {
        input: "http://secure-wallet-update-login.top/auth",
        analyzedAt: "scenario",
        keywordHits: ["secure", "wallet", "login", "auth"],
      },
      campaign: {
        type: "credential-phishing",
        spread: "email + SMS",
        targetGroup: "consumer wallet users",
      },
    },
    findings: [
      {
        source: "url-triage",
        title: "Credential-lure wording detected",
        detail: "Keywords observed: secure, wallet, login, auth.",
        severity: "high",
        confidence: 0.89,
      },
      {
        source: "url-triage",
        title: "High-risk TLD observed (.top)",
        detail: "The target domain uses a high-risk TLD frequently seen in low-reputation campaigns.",
        severity: "medium",
        confidence: 0.77,
      },
      {
        source: "url-triage",
        title: "Non-HTTPS URL detected",
        detail: "The landing page is delivered over HTTP, enabling interception and tampering.",
        severity: "high",
        confidence: 0.92,
      },
      {
        source: "response-gap",
        title: "No user comms workflow attached",
        detail: "There is no immediate outbound guidance prepared for potentially affected users.",
        severity: "medium",
        confidence: 0.7,
      },
    ],
  },
  "shadow-network": {
    title: "Shadow Network",
    goal: "Draft a fast hardening plan for insecure transport, weak browser posture, and telemetry blind spots.",
    signals: {
      networkSignals: {
        online: true,
        protocol: "http:",
        host: "portal.internal",
        effectiveType: "2g",
        downlinkMbps: 0.6,
        rttMs: 520,
        saveData: true,
        localIps: ["192.168.0.12"],
      },
      permissions: {
        notifications: "denied",
        geolocation: "prompt",
        clipboardRead: "unsupported",
      },
    },
    findings: [
      {
        source: "network-signals",
        title: "Insecure transport protocol detected",
        detail: "The active host is using HTTP instead of HTTPS.",
        severity: "high",
        confidence: 0.93,
      },
      {
        source: "permission-audit",
        title: "notifications permission is denied",
        detail: "Blocked permission can break alerting and user-facing incident flows.",
        severity: "medium",
        confidence: 0.84,
      },
      {
        source: "network-signals",
        title: "Low-bandwidth link detected",
        detail: "Constrained network conditions may prevent timely upload of response telemetry.",
        severity: "low",
        confidence: 0.63,
      },
      {
        source: "network-signals",
        title: "Local network interfaces discovered",
        detail: "Detected local IP candidates: 192.168.0.12.",
        severity: "info",
        confidence: 0.52,
      },
    ],
  },
  "rogue-device": {
    title: "Rogue Device",
    goal: "Prioritize BLE containment, endpoint trust checks, and short-term monitoring actions.",
    signals: {
      bluetooth: {
        supported: true,
        secureContext: true,
      },
      bluetoothDevice: {
        id: "rogue-speaker-01",
        name: "Unknown Beacon",
      },
      deviceSurface: {
        platform: "Win32",
        secureContext: true,
        cookieEnabled: false,
      },
    },
    findings: [
      {
        source: "permission-request",
        title: "Bluetooth device access granted",
        detail: "Selected BLE device: Unknown Beacon.",
        severity: "info",
        confidence: 0.7,
      },
      {
        source: "device-surface",
        title: "Cookies disabled",
        detail: "Cookie-disabled environments can break secure auth and session continuity.",
        severity: "low",
        confidence: 0.63,
      },
      {
        source: "bluetooth",
        title: "Unexpected BLE signal inside secure zone",
        detail: "A nearby device was observed in a workflow that does not normally require BLE access.",
        severity: "high",
        confidence: 0.81,
      },
      {
        source: "network-signals",
        title: "Local network interfaces discovered",
        detail: "Detected local IP candidates: 10.10.24.18, 192.168.10.5.",
        severity: "info",
        confidence: 0.51,
      },
    ],
  },
  "rapid-hardening": {
    title: "Rapid Hardening",
    goal: "Create a 48-hour hardening sprint with specific ownership, prioritization, and API-first follow-up.",
    signals: {
      hardeningBacklog: {
        ownerCoverage: "partial",
        sprintWindowHours: 48,
        blockers: ["missing alert routing", "manual export only"],
      },
    },
    findings: [
      {
        source: "program",
        title: "Critical findings have no assigned owner",
        detail: "The current incident lane lacks named ownership for the highest-severity issues.",
        severity: "critical",
        confidence: 0.88,
      },
      {
        source: "program",
        title: "Response actions are still manual",
        detail: "Operators must manually export state and communicate the next steps.",
        severity: "medium",
        confidence: 0.79,
      },
      {
        source: "program",
        title: "Recent incident context is not persisted beyond ingest",
        detail: "The product stores events but has no dashboard workflow for reviewing them in place.",
        severity: "medium",
        confidence: 0.74,
      },
      {
        source: "program",
        title: "Hardening sprint requested",
        detail: "This scenario is tuned for roadmap-style Gemini output and execution planning.",
        severity: "info",
        confidence: 0.96,
      },
    ],
  },
};

const engine = new RiskEngine();
let isBusy = false;

const state = {
  filters: {
    query: "",
    severity: "all",
  },
  health: {
    apiOnline: false,
    geminiConfigured: false,
    uptimeSec: null,
    lastSyncText: "--",
  },
  events: [],
  selectedEventId: null,
  intervalsStarted: false,
};

const elements = {
  overallScore: document.getElementById("overallScore"),
  findingCount: document.getElementById("findingCount"),
  criticalCount: document.getElementById("criticalCount"),
  signalCount: document.getElementById("signalCount"),
  statusText: document.getElementById("statusText"),
  findingsList: document.getElementById("findingsList"),
  findingFilterMeta: document.getElementById("findingFilterMeta"),
  contextOutput: document.getElementById("contextOutput"),
  aiOutput: document.getElementById("aiOutput"),
  eventDetailOutput: document.getElementById("eventDetailOutput"),
  activityLog: document.getElementById("activityLog"),
  eventsList: document.getElementById("eventsList"),
  runScanBtn: document.getElementById("runScanBtn"),
  heroScanBtn: document.getElementById("heroScanBtn"),
  permissionsBtn: document.getElementById("permissionsBtn"),
  analyzeUrlBtn: document.getElementById("analyzeUrlBtn"),
  exportBtn: document.getElementById("exportBtn"),
  pushBtn: document.getElementById("pushBtn"),
  generatePlanBtn: document.getElementById("generatePlanBtn"),
  copyAiBtn: document.getElementById("copyAiBtn"),
  copyContextBtn: document.getElementById("copyContextBtn"),
  refreshEventsBtn: document.getElementById("refreshEventsBtn"),
  refreshHealthBtn: document.getElementById("refreshHealthBtn"),
  loadDefaultGoalBtn: document.getElementById("loadDefaultGoalBtn"),
  urlInput: document.getElementById("urlInput"),
  goalInput: document.getElementById("goalInput"),
  findingSearchInput: document.getElementById("findingSearchInput"),
  healthStatusValue: document.getElementById("healthStatusValue"),
  geminiStatusValue: document.getElementById("geminiStatusValue"),
  uptimeValue: document.getElementById("uptimeValue"),
  lastSyncValue: document.getElementById("lastSyncValue"),
  statusMirrors: document.querySelectorAll("[data-status-mirror]"),
  scoreMirrors: document.querySelectorAll("[data-score-mirror]"),
  findingMirrors: document.querySelectorAll("[data-finding-mirror]"),
  criticalMirrors: document.querySelectorAll("[data-critical-mirror]"),
  signalMirrors: document.querySelectorAll("[data-signal-mirror]"),
  eventCountMirrors: document.querySelectorAll("[data-event-count-mirror]"),
  shortcutTriggers: document.querySelectorAll("[data-scroll-target], [data-action], [data-focus-target]"),
  revealTargets: document.querySelectorAll("[data-reveal]"),
  severityFilterButtons: document.querySelectorAll("[data-filter-severity]"),
  scenarioButtons: document.querySelectorAll("[data-scenario-id]"),
};

init();

function init() {
  bindCoreEvents();
  bindShortcutTriggers();
  initRevealObserver();
  updateStatus("Idle");
  elements.goalInput.value = DEFAULT_GOAL;
  renderSeverityFilterState();
  refreshUi();
  renderHealth();
  renderEvents();
  logActivity("NightWatch Sentinel loaded. Ready for scan.");
  void syncBackgroundState({ logHealth: true });
  startBackgroundPolling();
}

function bindCoreEvents() {
  elements.runScanBtn?.addEventListener("click", runFullScan);
  elements.heroScanBtn?.addEventListener("click", runFullScan);
  elements.permissionsBtn?.addEventListener("click", requestHighValuePermissions);
  elements.analyzeUrlBtn?.addEventListener("click", performUrlAnalysis);
  elements.exportBtn?.addEventListener("click", exportReport);
  elements.pushBtn?.addEventListener("click", pushEventPayload);
  elements.generatePlanBtn?.addEventListener("click", generateAiPlaybook);
  elements.copyAiBtn?.addEventListener("click", () =>
    copyTextToClipboard(elements.aiOutput.textContent, "AI output copied to clipboard.")
  );
  elements.copyContextBtn?.addEventListener("click", () =>
    copyTextToClipboard(elements.contextOutput.textContent, "Context JSON copied to clipboard.")
  );
  elements.refreshEventsBtn?.addEventListener("click", () => void refreshEvents(true));
  elements.refreshHealthBtn?.addEventListener("click", () => void fetchHealth(true));
  elements.loadDefaultGoalBtn?.addEventListener("click", () => {
    elements.goalInput.value = DEFAULT_GOAL;
    logActivity("Default Gemini goal restored.");
  });

  elements.findingSearchInput?.addEventListener("input", (event) => {
    state.filters.query = event.target.value.trim().toLowerCase();
    renderFindings(engine.getContext().findings);
  });

  for (const button of elements.severityFilterButtons) {
    button.addEventListener("click", () => {
      state.filters.severity = button.dataset.filterSeverity || "all";
      renderSeverityFilterState();
      renderFindings(engine.getContext().findings);
    });
  }

  for (const button of elements.scenarioButtons) {
    button.addEventListener("click", () => {
      const scenarioId = button.dataset.scenarioId;
      if (scenarioId) {
        loadScenario(scenarioId);
      }
    });
  }

  elements.urlInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      performUrlAnalysis();
    }
  });

  elements.goalInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      void generateAiPlaybook();
    }
  });

  document.addEventListener("keydown", handleGlobalHotkeys);
}

function bindShortcutTriggers() {
  for (const trigger of elements.shortcutTriggers) {
    trigger.addEventListener("click", handleShortcutClick);

    if (trigger.tagName !== "BUTTON") {
      trigger.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activateTrigger(trigger);
        }
      });
    }
  }
}

function handleShortcutClick(event) {
  const trigger = event.currentTarget;
  const hasCustomBehavior =
    Boolean(trigger.dataset.scrollTarget) ||
    Boolean(trigger.dataset.action) ||
    Boolean(trigger.dataset.focusTarget);

  if (hasCustomBehavior && trigger.tagName !== "BUTTON") {
    event.preventDefault();
  }

  activateTrigger(trigger);
}

function activateTrigger(trigger) {
  const { scrollTarget, focusTarget, action } = trigger.dataset;

  if (scrollTarget) {
    scrollToSection(scrollTarget);
  }

  if (focusTarget) {
    queueFocus(focusTarget, scrollTarget ? 360 : 60);
  }

  if (action) {
    void runShortcutAction(action);
  }
}

async function runShortcutAction(action) {
  if (isBusy) {
    logActivity("Action skipped while another operation is still running.", "warning");
    return;
  }

  switch (action) {
    case "push-event":
      await pushEventPayload();
      break;
    case "generate-playbook":
      await generateAiPlaybook();
      break;
    case "export-report":
      exportReport();
      break;
    default:
      break;
  }
}

function handleGlobalHotkeys(event) {
  const target = event.target;
  const tagName = target?.tagName || "";
  const isTypingSurface =
    tagName === "INPUT" ||
    tagName === "TEXTAREA" ||
    target?.isContentEditable;

  if (isTypingSurface || event.ctrlKey || event.metaKey || event.altKey) {
    return;
  }

  const key = event.key.toLowerCase();
  switch (key) {
    case "/":
      event.preventDefault();
      scrollToSection("opsDeck");
      queueFocus("urlInput", 260);
      break;
    case "g":
      event.preventDefault();
      scrollToSection("playbookDeck");
      queueFocus("goalInput", 260);
      break;
    case "r":
      event.preventDefault();
      void runFullScan();
      break;
    case "e":
      event.preventDefault();
      void refreshEvents(true);
      break;
    default:
      break;
  }
}

async function runFullScan() {
  if (isBusy) {
    return;
  }

  setBusyState("Running full scan");
  engine.reset();
  refreshUi();
  logActivity("Scan initiated.");

  try {
    const scanResults = await Promise.allSettled([
      runPermissionAudit(engine),
      runDeviceSurfaceAudit(engine),
      runNetworkSignalAudit(engine),
      runBluetoothAudit(engine),
    ]);

    const failures = scanResults.filter((r) => r.status === "rejected");
    if (failures.length > 0) {
      for (const failure of failures) {
        engine.addFinding({
          source: "scan-orchestrator",
          title: "Analyzer module failed",
          detail: String(failure.reason?.message || failure.reason),
          severity: "low",
          confidence: 0.7,
        });
      }
    }

    engine.finish();
    refreshUi();
    flashPanel("findingsDeck");
    logActivity(`Full threat scan completed. ${failures.length > 0 ? `${failures.length} module(s) had errors.` : ""}`);
  } catch (error) {
    logActivity(`Scan failed: ${error.message}`, "error");
  } finally {
    clearBusyState();
  }
}

async function requestHighValuePermissions() {
  if (isBusy) {
    return;
  }

  setBusyState("Requesting permissions");
  logActivity("Permission request workflow started.");

  const workflows = [
    requestNotificationPermission,
    requestMediaPermission,
    requestLocationPermission,
    requestBluetoothPermission,
  ];

  try {
    for (const workflow of workflows) {
      try {
        await workflow();
      } catch (error) {
        engine.addFinding({
          source: "permission-request",
          title: "Permission workflow error",
          detail: String(error?.message || error),
          severity: "low",
          confidence: 0.7,
        });
      }
    }

    refreshUi();
    flashPanel("findingsDeck");
    logActivity("Permission request workflow completed.");
  } finally {
    clearBusyState();
  }
}

async function requestNotificationPermission() {
  if (!window.Notification || !Notification.requestPermission) {
    engine.addFinding({
      source: "permission-request",
      title: "Notification API unavailable",
      detail: "Browser does not support Notification permission workflow.",
      severity: "low",
      confidence: 0.8,
    });
    return;
  }

  const result = await Notification.requestPermission();
  engine.addFinding({
    source: "permission-request",
    title: `Notification permission: ${result}`,
    detail: "Captured from interactive permission prompt.",
    severity: result === "denied" ? "medium" : "info",
    confidence: 0.75,
  });
}

async function requestMediaPermission() {
  if (!navigator.mediaDevices?.getUserMedia) {
    engine.addFinding({
      source: "permission-request",
      title: "Media devices API unavailable",
      detail: "Cannot request camera/microphone access in this browser.",
      severity: "low",
      confidence: 0.82,
    });
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    for (const track of stream.getTracks()) {
      track.stop();
    }
    engine.addFinding({
      source: "permission-request",
      title: "Camera and microphone permission granted",
      detail: "Media stream access succeeded during controlled prompt.",
      severity: "info",
      confidence: 0.9,
    });
  } catch (error) {
    engine.addFinding({
      source: "permission-request",
      title: "Camera/microphone permission denied or blocked",
      detail: String(error.message || error),
      severity: "medium",
      confidence: 0.86,
    });
  }
}

async function requestLocationPermission() {
  if (!navigator.geolocation?.getCurrentPosition) {
    engine.addFinding({
      source: "permission-request",
      title: "Geolocation API unavailable",
      detail: "Cannot request location in this browser.",
      severity: "low",
      confidence: 0.8,
    });
    return;
  }

  const result = await new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (position) => resolve({ ok: true, position }),
      (error) => resolve({ ok: false, error }),
      { enableHighAccuracy: false, timeout: 8000, maximumAge: 0 }
    );
  });

  if (result.ok) {
    const { latitude, longitude } = result.position.coords;
    engine.setSignal("lastLocation", {
      latitude,
      longitude,
      accuracy: result.position.coords.accuracy,
    });
    engine.addFinding({
      source: "permission-request",
      title: "Geolocation permission granted",
      detail: "Location captured for optional network anomaly context.",
      severity: "info",
      confidence: 0.74,
    });
  } else {
    engine.addFinding({
      source: "permission-request",
      title: "Geolocation permission denied or timed out",
      detail: String(result.error?.message || "Location prompt rejected."),
      severity: "low",
      confidence: 0.78,
    });
  }
}

async function requestBluetoothPermission() {
  if (!navigator.bluetooth?.requestDevice) {
    engine.addFinding({
      source: "permission-request",
      title: "Web Bluetooth request flow unavailable",
      detail: "Cannot request BLE device access in this environment.",
      severity: "low",
      confidence: 0.76,
    });
    return;
  }

  try {
    const device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true });
    engine.setSignal("bluetoothDevice", {
      id: device.id,
      name: device.name || "Unnamed device",
    });
    engine.addFinding({
      source: "permission-request",
      title: "Bluetooth device access granted",
      detail: `Selected BLE device: ${device.name || "Unnamed device"}`,
      severity: "info",
      confidence: 0.7,
    });
  } catch (error) {
    const isNotFound = String(error?.name || "").toLowerCase() === "notfounderror";
    engine.addFinding({
      source: "permission-request",
      title: "Bluetooth device request not completed",
      detail: String(error.message || error),
      severity: isNotFound ? "low" : "medium",
      confidence: 0.71,
    });
  }
}

function performUrlAnalysis() {
  const rawUrl = elements.urlInput.value.trim();
  if (!rawUrl) {
    logActivity("No URL entered for triage.", "warning");
    return;
  }
  analyzeUrlHeuristics(engine, rawUrl);
  refreshUi();
  flashPanel("findingsDeck");
  logActivity("URL threat triage completed.");
}

function loadScenario(scenarioId) {
  const scenario = SCENARIOS[scenarioId];
  if (!scenario) {
    return;
  }

  engine.reset();
  for (const [key, value] of Object.entries(scenario.signals || {})) {
    engine.setSignal(key, value);
  }
  for (const finding of scenario.findings || []) {
    engine.addFinding(finding);
  }
  engine.finish();
  elements.goalInput.value = scenario.goal || DEFAULT_GOAL;
  elements.aiOutput.textContent = `Scenario loaded: ${scenario.title}\n\nGenerate a Gemini playbook to continue.`;
  state.filters.query = "";
  state.filters.severity = "all";
  elements.findingSearchInput.value = "";
  renderSeverityFilterState();
  refreshUi();
  flashPanel("findingsDeck");
  flashPanel("playbookDeck");
  logActivity(`Scenario loaded: ${scenario.title}.`);
}

function exportReport() {
  const context = engine.getContext();
  const data = JSON.stringify(context, null, 2);
  const blob = new Blob([data], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `nightwatch-report-${Date.now()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
  flashPanel("contextDeck");
  logActivity("JSON report exported.");
}

async function pushEventPayload() {
  if (isBusy) {
    return;
  }

  setBusyState("Pushing event");
  try {
    const response = await fetch("/api/events/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: "nightwatch-sentinel-ui",
        context: engine.getContext(),
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error || "Event ingest failed.");
    }
    await refreshEvents(false);
    flashPanel("relayDeck");
    logActivity(`Event pushed to API (id: ${data.id}).`);
  } catch (error) {
    logActivity(`Event push failed: ${error.message}`, "error");
  } finally {
    clearBusyState();
  }
}

async function generateAiPlaybook() {
  if (isBusy) {
    return;
  }

  setBusyState("Generating Gemini playbook");
  elements.aiOutput.textContent = "Generating response from Gemini...";

  try {
    const response = await fetch("/api/gemini/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        context: engine.getContext(),
        userGoal: elements.goalInput.value || DEFAULT_GOAL,
      }),
    });
    const data = await response.json();
    if (response.status === 429) {
      elements.aiOutput.textContent = data?.detail || "Rate limit exceeded. Wait a moment and try again.";
      logActivity("Gemini rate limit reached.", "warning");
      flashPanel("playbookDeck");
      return;
    }
    if (!response.ok || !data.ok) {
      elements.aiOutput.textContent = data?.text || data?.message || "Gemini request failed.";
      logActivity("Gemini playbook generation failed.", "warning");
      flashPanel("playbookDeck");
      return;
    }

    elements.aiOutput.textContent = data.text;
    flashPanel("playbookDeck");
    logActivity("Gemini playbook generated.");
  } catch (error) {
    elements.aiOutput.textContent = `Failed to call Gemini: ${error.message}`;
    logActivity(`Gemini call failed: ${error.message}`, "error");
    flashPanel("playbookDeck");
  } finally {
    clearBusyState();
  }
}

async function syncBackgroundState(options = {}) {
  await Promise.all([fetchHealth(Boolean(options.logHealth)), refreshEvents(false)]);
}

async function fetchHealth(logResult = false) {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    state.health.apiOnline = Boolean(response.ok && data?.status === "ok");
    state.health.geminiConfigured = Boolean(data?.geminiConfigured);
    state.health.uptimeSec = Number(data?.uptimeSec ?? 0);
    state.health.lastSyncText = formatTimestamp(new Date());
    renderHealth();

    if (logResult) {
      if (data?.geminiConfigured) {
        logActivity("Gemini key detected in backend environment.");
      } else {
        logActivity("Gemini key missing. Add GEMINI_API_KEY in .env.", "warning");
      }
    }
  } catch {
    state.health.apiOnline = false;
    state.health.lastSyncText = formatTimestamp(new Date());
    renderHealth();
    if (logResult) {
      logActivity("Health check failed. Ensure server is running.", "error");
    }
  }
}

async function refreshEvents(logResult = false) {
  try {
    const response = await fetch("/api/events");
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error || "Failed to fetch events.");
    }

    state.events = Array.isArray(data?.items) ? data.items.slice().reverse() : [];
    if (!state.selectedEventId || !state.events.some((event) => event.id === state.selectedEventId)) {
      state.selectedEventId = state.events[0]?.id || null;
    }
    syncText(elements.eventCountMirrors, String(data?.count ?? state.events.length));
    renderEvents();

    if (logResult) {
      logActivity(`Event relay refreshed (${state.events.length} recent item${state.events.length === 1 ? "" : "s"}).`);
    }
  } catch (error) {
    if (logResult) {
      logActivity(`Event relay refresh failed: ${error.message}`, "error");
    }
    state.events = [];
    state.selectedEventId = null;
    syncText(elements.eventCountMirrors, "0");
    renderEvents();
  }
}

function refreshUi() {
  const summary = engine.getSummary();

  elements.overallScore.textContent = `${summary.score} / 100`;
  elements.findingCount.textContent = String(summary.totalFindings);
  elements.criticalCount.textContent = String(summary.criticalPlusHigh);
  elements.signalCount.textContent = String(summary.signalCount);

  syncText(elements.scoreMirrors, `${summary.score} / 100`);
  syncText(elements.findingMirrors, String(summary.totalFindings));
  syncText(elements.criticalMirrors, String(summary.criticalPlusHigh));
  syncText(elements.signalMirrors, String(summary.signalCount));

  renderFindings(engine.getContext().findings);
  elements.contextOutput.textContent = JSON.stringify(engine.getContext(), null, 2);
}

function renderFindings(findings) {
  const filteredFindings = applyFindingFilters(findings);
  elements.findingFilterMeta.textContent = `Showing ${filteredFindings.length} of ${findings.length} findings`;

  if (!filteredFindings.length) {
    const message = findings.length
      ? "No findings match the current filter."
      : "No findings yet. Run a scan or load a scenario to populate telemetry.";
    elements.findingsList.innerHTML = `<li class='finding-item'><p>${message}</p></li>`;
    return;
  }

  const html = filteredFindings
    .slice()
    .reverse()
    .map((finding) => {
      const safeTitle = escapeHtml(finding.title);
      const safeDetail = escapeHtml(finding.detail || "No detail available.");
      const safeSource = escapeHtml(finding.source || "unknown");
      const severityClass = `severity-${finding.severity}`;
      return `
        <li class="finding-item">
          <p class="finding-title">
            <strong>${safeTitle}</strong>
            <span class="pill ${severityClass}">${finding.severity}</span>
          </p>
          <p>${safeDetail}</p>
          <p><small>source: ${safeSource} | confidence: ${(finding.confidence * 100).toFixed(0)}%</small></p>
        </li>
      `;
    })
    .join("");

  elements.findingsList.innerHTML = html;
}

function applyFindingFilters(findings) {
  return findings.filter((finding) => {
    const matchesSeverity =
      state.filters.severity === "all" || finding.severity === state.filters.severity;

    if (!matchesSeverity) {
      return false;
    }

    if (!state.filters.query) {
      return true;
    }

    const haystack = [finding.title, finding.detail, finding.source].join(" ").toLowerCase();
    return haystack.includes(state.filters.query);
  });
}

function renderSeverityFilterState() {
  for (const button of elements.severityFilterButtons) {
    const isActive = button.dataset.filterSeverity === state.filters.severity;
    button.classList.toggle("is-active", isActive);
  }
}

function renderHealth() {
  elements.healthStatusValue.textContent = state.health.apiOnline ? "online" : "offline";
  elements.geminiStatusValue.textContent = state.health.geminiConfigured ? "configured" : "missing";
  elements.uptimeValue.textContent =
    state.health.uptimeSec === null ? "--" : `${Math.round(state.health.uptimeSec)}s`;
  elements.lastSyncValue.textContent = state.health.lastSyncText;
}

function renderEvents() {
  if (!state.events.length) {
    elements.eventsList.innerHTML =
      "<li class='event-item'><strong>No stored events</strong><p>Push a payload or refresh the relay.</p></li>";
    elements.eventDetailOutput.textContent = "No event selected.";
    return;
  }

  const activeEvent = state.events.find((event) => event.id === state.selectedEventId) || state.events[0];
  state.selectedEventId = activeEvent?.id || null;

  const itemsHtml = state.events
    .map((event) => {
      const isActive = event.id === state.selectedEventId;
      const payloadSource = escapeHtml(event.payload?.source || event.source || "unknown");
      const receivedAt = escapeHtml(event.receivedAt || "");
      return `
        <li>
          <button type="button" class="event-item ${isActive ? "is-active" : ""}" data-event-id="${escapeHtml(event.id)}">
            <strong>${payloadSource}</strong>
            <p>${receivedAt}</p>
          </button>
        </li>
      `;
    })
    .join("");

  elements.eventsList.innerHTML = itemsHtml;

  for (const button of elements.eventsList.querySelectorAll("[data-event-id]")) {
    button.addEventListener("click", () => {
      state.selectedEventId = button.dataset.eventId;
      renderEvents();
    });
  }

  elements.eventDetailOutput.textContent = JSON.stringify(activeEvent, null, 2);
}

function setBusyState(message) {
  isBusy = true;
  updateStatus(message);

  for (const button of getBusyLockedButtons()) {
    button.disabled = true;
  }
}

function clearBusyState() {
  isBusy = false;
  updateStatus("Idle");

  for (const button of getBusyLockedButtons()) {
    button.disabled = false;
  }

  refreshUi();
}

function updateStatus(message) {
  elements.statusText.textContent = message;
  syncText(elements.statusMirrors, message);
}

function getBusyLockedButtons() {
  return [
    elements.runScanBtn,
    elements.heroScanBtn,
    elements.permissionsBtn,
    elements.analyzeUrlBtn,
    elements.exportBtn,
    elements.pushBtn,
    elements.generatePlanBtn,
  ].filter(Boolean);
}

function logActivity(message, level = "info") {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");

  const item = document.createElement("li");
  item.className = `log-item ${level === "warning" ? "log-warning" : ""} ${
    level === "error" ? "log-error" : ""
  }`.trim();
  item.innerHTML = `<p><span class="log-time">[${hh}:${mm}:${ss}]</span>${escapeHtml(message)}</p>`;
  elements.activityLog.prepend(item);
}

async function copyTextToClipboard(text, successMessage) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      fallbackCopy(text);
    }
    logActivity(successMessage);
  } catch (error) {
    logActivity(`Clipboard copy failed: ${error.message}`, "error");
  }
}

function fallbackCopy(text) {
  const input = document.createElement("textarea");
  input.value = text;
  document.body.append(input);
  input.select();
  document.execCommand("copy");
  input.remove();
}

function syncText(nodeList, value) {
  for (const node of nodeList) {
    node.textContent = value;
  }
}

function scrollToSection(sectionId) {
  const section = document.getElementById(sectionId);
  if (!section) {
    return;
  }

  section.scrollIntoView({ behavior: "smooth", block: "start" });
  flashPanel(sectionId);
}

function queueFocus(elementId, delayMs) {
  window.setTimeout(() => {
    const node = document.getElementById(elementId);
    node?.focus({ preventScroll: true });
  }, delayMs);
}

function flashPanel(elementId) {
  const root = document.getElementById(elementId);
  if (!root) {
    return;
  }

  const panel = root.classList.contains("panel") ? root : root.querySelector(".panel");
  if (!panel) {
    return;
  }

  panel.classList.remove("panel-flash");
  void panel.offsetWidth;
  panel.classList.add("panel-flash");
  window.setTimeout(() => panel.classList.remove("panel-flash"), 950);
}

function initRevealObserver() {
  if (!("IntersectionObserver" in window)) {
    for (const target of elements.revealTargets) {
      target.classList.add("is-visible");
    }
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      }
    },
    { threshold: 0.1 }
  );

  for (const target of elements.revealTargets) {
    observer.observe(target);
  }
}

function startBackgroundPolling() {
  if (state.intervalsStarted) {
    return;
  }

  state.intervalsStarted = true;
  window.setInterval(() => {
    void fetchHealth(false);
    void refreshEvents(false);
  }, POLL_INTERVAL_MS);
}

function formatTimestamp(date) {
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  const ss = String(date.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
