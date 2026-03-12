const SEVERITY_POINTS = {
  critical: 30,
  high: 20,
  medium: 11,
  low: 5,
  info: 1,
};

// Calibrated so ~8–9 mixed-severity findings reach 100.
// Formula: score = min(100, round((rawScore / MAX_RAW_SCORE) * 100))
const MAX_RAW_SCORE = 260;

let idCounter = 0;

export class RiskEngine {
  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      startedAt: new Date().toISOString(),
      finishedAt: null,
      findings: [],
      signals: {},
    };
  }

  addFinding(input) {
    const severity = normalizeSeverity(input?.severity);
    const title = input?.title || "Unnamed finding";
    const source = input?.source || "analyzer";

    // Deduplicate identical findings from the same source
    const isDuplicate = this.state.findings.some(
      (f) => f.source === source && f.title === title && f.severity === severity
    );
    if (isDuplicate) {
      return null;
    }

    idCounter += 1;
    const finding = {
      id: `${Date.now()}-${idCounter.toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      source,
      title,
      detail: input?.detail || "",
      severity,
      confidence: clamp(Number(input?.confidence ?? 0.65), 0.1, 1),
      createdAt: new Date().toISOString(),
    };
    this.state.findings.push(finding);
    return finding;
  }

  setSignal(key, value) {
    if (!key) {
      return;
    }
    this.state.signals[key] = value;
  }

  finish() {
    this.state.finishedAt = new Date().toISOString();
  }

  getSummary() {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    let rawScore = 0;
    for (const finding of this.state.findings) {
      counts[finding.severity] += 1;
      rawScore += (SEVERITY_POINTS[finding.severity] || 0) * finding.confidence;
    }

    const score = Math.min(100, Math.round((rawScore / MAX_RAW_SCORE) * 100));
    const tier =
      score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : score > 0 ? "low" : "clear";
    return {
      score,
      tier,
      totalFindings: this.state.findings.length,
      criticalPlusHigh: counts.critical + counts.high,
      signalCount: Object.keys(this.state.signals).length,
      counts,
    };
  }

  getContext() {
    return {
      ...this.state,
      summary: this.getSummary(),
    };
  }
}

function normalizeSeverity(severity) {
  if (typeof severity !== "string") {
    return "low";
  }
  const clean = severity.toLowerCase();
  if (SEVERITY_POINTS[clean] !== undefined) {
    return clean;
  }
  return "low";
}

function clamp(value, min, max) {
  if (Number.isNaN(value)) {
    return min;
  }
  return Math.max(min, Math.min(max, value));
}

