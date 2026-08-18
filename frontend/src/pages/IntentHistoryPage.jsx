import { useState } from "react";
import { History, Info } from "lucide-react";
import LifecyclePill from "../components/ui/LifecyclePill";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { transitionIntent } from "../services/api";

const STATES = ["draft", "approved", "used", "expired", "archived", "destroyed"];

export default function IntentHistoryPage({ shared }) {
  const [intentId, setIntentId] = useState(shared?.intentId ?? "");
  const [targetState, setTargetState] = useState("approved");
  const [reason, setReason] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleTransition(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await transitionIntent(Number(intentId), targetState, reason);
      setResult(response);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Transition failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <PageHeader
        icon="history"
        eyebrow="Intent-Bound Cryptography"
        title="Intent Lifecycle"
        description="Draft → Approved → Used → Expired → Archived → Destroyed. Every intent version is immutable; transitions are logged to the audit chain."
      />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">Apply a Transition</h2>
        <form onSubmit={handleTransition}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Intent ID">
              <TextField type="number" value={intentId} onChange={(e) => setIntentId(e.target.value)} required />
            </Field>
            <Field label="Target State">
              <SelectField value={targetState} onChange={(e) => setTargetState(e.target.value)}>
                {STATES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </SelectField>
            </Field>
          </div>
          <Field label="Reason">
            <TextField value={reason} onChange={(e) => setReason(e.target.value)} required />
          </Field>

          <Alert type="error">{error}</Alert>

          <Button type="submit" variant="accent" accent="sky" full loading={loading} icon={History}>
            Apply Transition
          </Button>
        </form>
      </div>

      {result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-3">Transition Applied</h2>
          <div className="flex items-center gap-2.5">
            <LifecyclePill state={result.lifecycle_state} />
            <code className="text-[13px] text-cq-on-surface-variant font-mono">
              intent #{result.intent_id} · v{result.version_number}
            </code>
          </div>
        </div>
      )}

      <div className="mt-6 flex items-start gap-2.5 rounded-cq-md bg-cq-primary-container/10 px-4 py-3.5 text-[13px] leading-relaxed text-cq-on-surface-variant">
        <Info size={16} className="shrink-0 mt-0.5 text-cq-primary" />
        <span>
          The lifecycle state machine only allows forward transitions (with Used → Used permitted,
          for reuse within the intent's validity window). Attempting an invalid transition (e.g.
          Draft → Used, or transitioning a Destroyed intent) is rejected and logged.
        </span>
      </div>
    </div>
  );
}
