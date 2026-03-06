const SEVERITY_POINTS = {
  critical: 30,
  high: 20,
  medium: 11,
  low: 5,
  info: 1,
};

const MAX_RAW_SCORE = 260;

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
    const finding = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      source: input?.source || "analyzer",
      title: input?.title || "Unnamed finding",
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
    return {
      score,
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

