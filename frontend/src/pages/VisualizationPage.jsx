import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { Gauge, ActivitySquare } from "lucide-react";
import RiskPill from "../components/ui/RiskPill";
import { Toggle } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { assessRisk } from "../services/api";

// Recharts takes literal colors, not Tailwind classes.
const CQ = { primary: "#b8c3ff", outline: "#8e90a2", gridLine: "rgba(255,255,255,0.06)" };

function RangeField({ label, value, onChange, min, max, step = 1 }) {
  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[13px] font-semibold text-cq-on-surface-variant">{label}</span>
        <span className="text-[12.5px] font-mono text-cq-outline">{value}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={onChange}
        className="w-full h-1.5 rounded-full bg-cq-surface-container-highest accent-cq-primary cursor-pointer"
      />
    </div>
  );
}

export default function VisualizationPage() {
  const [qber, setQber] = useState(0);
  const [failedLogins, setFailedLogins] = useState(0);
  const [faceConfidence, setFaceConfidence] = useState(1);
  const [deviceMismatch, setDeviceMismatch] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [rapidAccess, setRapidAccess] = useState(0);
  const [policyFailures, setPolicyFailures] = useState(0);

  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function runAssessment() {
    setError("");
    setLoading(true);
    try {
      const response = await assessRisk({
        qber: Number(qber),
        failed_login_count: Number(failedLogins),
        face_confidence: Number(faceConfidence),
        device_mismatch: deviceMismatch,
        session_expired: sessionExpired,
        rapid_access_attempts: Number(rapidAccess),
        policy_failure_count: Number(policyFailures),
      });
      setResult(response);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Assessment failed");
    } finally {
      setLoading(false);
    }
  }

  // Client-side approximation of each factor's weight, purely for the
  // chart — the authoritative score always comes from /api/risk/assess.
  const chartData = [
    { name: "QBER", points: Math.min(qber, 1) * 40 },
    { name: "Failed logins", points: Math.min(failedLogins, 5) * 8 },
    { name: "Low face conf.", points: faceConfidence < 0.6 ? 25 : 0 },
    { name: "Device mismatch", points: deviceMismatch ? 30 : 0 },
    { name: "Session expired", points: sessionExpired ? 35 : 0 },
    { name: "Rapid access", points: Math.min(rapidAccess, 5) * 6 },
    { name: "Policy failures", points: Math.min(policyFailures, 4) * 15 },
  ];

  return (
    <div>
      <PageHeader
        icon="radar"
        eyebrow="Adaptive Risk Engine"
        title="Risk Analysis"
        description="Interact with the factors to see how the adaptive risk engine weighs each signal before a decrypt or encrypt request is validated."
      />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">Factors</h2>
          <RangeField label={`QBER: ${(qber * 100).toFixed(0)}%`} value={qber} onChange={(e) => setQber(e.target.value)} min={0} max={1} step={0.01} />
          <RangeField label={`Failed logins: ${failedLogins}`} value={failedLogins} onChange={(e) => setFailedLogins(e.target.value)} min={0} max={10} />
          <RangeField label={`Face confidence: ${Number(faceConfidence).toFixed(2)}`} value={faceConfidence} onChange={(e) => setFaceConfidence(e.target.value)} min={0} max={1} step={0.01} />
          <RangeField label={`Rapid access attempts: ${rapidAccess}`} value={rapidAccess} onChange={(e) => setRapidAccess(e.target.value)} min={0} max={10} />
          <RangeField label={`Policy failures: ${policyFailures}`} value={policyFailures} onChange={(e) => setPolicyFailures(e.target.value)} min={0} max={6} />

          <div className="flex items-center justify-between py-2">
            <Toggle checked={deviceMismatch} onChange={setDeviceMismatch} label="Device mismatch" />
          </div>
          <div className="flex items-center justify-between py-2 mb-3">
            <Toggle checked={sessionExpired} onChange={setSessionExpired} label="Session expired" />
          </div>

          <Alert type="error">{error}</Alert>

          <Button variant="brand" full onClick={runAssessment} loading={loading} icon={Gauge}>
            Assess Risk
          </Button>

          {result && (
            <div className="mt-5 flex items-center gap-4 rounded-cq-lg bg-cq-surface-container-high px-5 py-4">
              <div className="text-[32px] font-bold font-display text-cq-on-surface">{result.score}</div>
              <div>
                <RiskPill level={result.level} />
                <div className="mt-1 text-[12.5px] text-cq-on-surface-variant">action: {result.action}</div>
              </div>
            </div>
          )}
        </div>

        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-4">
            <ActivitySquare size={17} className="text-cq-primary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Factor Contributions</h2>
          </div>
          <ResponsiveContainer width="100%" height={340}>
            <BarChart data={chartData} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={CQ.gridLine} />
              <XAxis type="number" domain={[0, 40]} tick={{ fontSize: 12, fill: CQ.outline }} />
              <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 12, fill: "#c4c5d9" }} />
              <Tooltip
                contentStyle={{
                  borderRadius: 12,
                  border: "1px solid rgba(255,255,255,0.08)",
                  background: "#1d1f29",
                  color: "#e2e1ef",
                  fontSize: 13,
                }}
              />
              <Bar dataKey="points" fill={CQ.primary} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
