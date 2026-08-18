import { useState } from "react";
import { FileText, CheckCircle2, ArrowRight, ShieldCheck, ShieldQuestion, XCircle } from "lucide-react";
import CopyBox from "../components/CopyBox";
import LifecyclePill from "../components/ui/LifecyclePill";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { createIntent, transitionIntent, validateIntent } from "../services/api";

const OPERATIONS = ["encrypt", "decrypt", "read", "write", "share", "revoke"];

function isoLocalToUtc(value) {
  if (!value) return "";
  return new Date(value).toISOString();
}

const DEFAULT_FORM = {
  sender: "",
  receiver: "",
  purpose: "",
  resource: "",
  operation: "decrypt",
  device_id: "",
  session_id: "",
  valid_from: "",
  valid_until: "",
  classification: "",
  department: "",
  project: "",
};

export default function CreateIntentPage({ navigate }) {
  const [form, setForm] = useState(DEFAULT_FORM);
  const [reason, setReason] = useState("initial creation");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [approving, setApproving] = useState(false);
  const [eligibility, setEligibility] = useState(null);
  const [checkingEligibility, setCheckingEligibility] = useState(false);

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function checkEligibility(cid, intentId) {
    setCheckingEligibility(true);
    try {
      const validation = await validateIntent(cid, intentId);
      setEligibility(validation);
      return validation;
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to check approval eligibility");
      return null;
    } finally {
      setCheckingEligibility(false);
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    setEligibility(null);
    try {
      const cid = {
        sender: form.sender,
        receiver: form.receiver,
        purpose: form.purpose,
        resource: form.resource,
        operation: form.operation,
        device_id: form.device_id,
        session_id: form.session_id,
        valid_from: isoLocalToUtc(form.valid_from),
        valid_until: isoLocalToUtc(form.valid_until),
        classification: form.classification || null,
        department: form.department || null,
        project: form.project || null,
      };
      const response = await createIntent(cid, reason);
      setResult({ ...response, cid });
      // Intent Validation runs automatically the moment the intent
      // exists, so Approval Eligibility is known before anyone sees
      // an "Approve" button at all.
      await checkEligibility(cid, response.intent_id);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to create intent");
    } finally {
      setLoading(false);
    }
  }

  async function handleApprove() {
    if (!result) return;
    setError("");
    setApproving(true);
    try {
      // The backend re-validates approval-eligibility itself and will
      // refuse an ineligible approval regardless of what the UI
      // shows — this is just so the person isn't asked to press
      // "Approve" against state that's already known to fail.
      const updated = await transitionIntent(result.intent_id, "approved", "approved for encryption");
      setResult((r) => ({ ...r, lifecycle_state: updated.lifecycle_state }));
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to approve intent");
      // The rejection itself is new information about eligibility —
      // refresh the reported state so the UI doesn't keep showing
      // "eligible" after a rejected approval attempt.
      await checkEligibility(result.cid, result.intent_id);
    } finally {
      setApproving(false);
    }
  }

  return (
    <div>
      <PageHeader
        icon="center_focus_strong"
        eyebrow="Intent-Bound Cryptography"
        title="Intent Management"
        description="Define the Cryptographic Intent Descriptor (CID) that a quantum key will later be bound to. No key material is issued until an intent is created and approved."
      />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="mb-4">
          <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Descriptor</h2>
          <p className="text-[13px] text-cq-on-surface-variant mt-0.5">
            Every field below becomes part of the canonicalized, hashed intent context.
          </p>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Sender">
              <TextField value={form.sender} onChange={set("sender")} required />
            </Field>
            <Field label="Receiver">
              <TextField value={form.receiver} onChange={set("receiver")} required />
            </Field>
          </div>

          <Field label="Purpose">
            <TextField value={form.purpose} onChange={set("purpose")} required />
          </Field>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Resource">
              <TextField value={form.resource} onChange={set("resource")} required />
            </Field>
            <Field label="Operation">
              <SelectField value={form.operation} onChange={set("operation")}>
                {OPERATIONS.map((op) => (
                  <option key={op} value={op}>{op}</option>
                ))}
              </SelectField>
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Device ID">
              <TextField value={form.device_id} onChange={set("device_id")} required />
            </Field>
            <Field label="Session ID">
              <TextField value={form.session_id} onChange={set("session_id")} required />
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Valid From">
              <TextField type="datetime-local" value={form.valid_from} onChange={set("valid_from")} required />
            </Field>
            <Field label="Valid Until">
              <TextField type="datetime-local" value={form.valid_until} onChange={set("valid_until")} required />
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Classification" hint="optional">
              <TextField value={form.classification} onChange={set("classification")} />
            </Field>
            <Field label="Department" hint="optional">
              <TextField value={form.department} onChange={set("department")} />
            </Field>
          </div>

          <Field label="Project" hint="optional">
            <TextField value={form.project} onChange={set("project")} />
          </Field>

          <Field label="Reason for this version">
            <TextField value={reason} onChange={(e) => setReason(e.target.value)} required />
          </Field>

          <Alert type="error">{error}</Alert>

          <Button type="submit" variant="brand" full loading={loading} icon={FileText}>
            Create Intent
          </Button>
        </form>
      </div>

      {result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Created</h2>
          </div>
          <div className="flex items-center gap-2.5 my-3">
            <LifecyclePill state={result.lifecycle_state} />
            <code className="text-[13px] text-cq-on-surface-variant font-mono">intent #{result.intent_id}</code>
          </div>
          <CopyBox label="Intent Hash (SHA-256 of canonical CID)" value={result.intent_hash} />

          {result.lifecycle_state === "draft" && (
            <div className="mt-4 rounded-cq-lg border px-4 py-3" style={{
              borderColor: eligibility?.approval_eligible ? "rgba(99,247,255,0.25)" : "rgba(251,191,36,0.25)",
              background: eligibility?.approval_eligible ? "rgba(99,247,255,0.08)" : "rgba(251,191,36,0.08)",
            }}>
              <div className="flex items-center gap-2">
                {checkingEligibility ? (
                  <ShieldQuestion size={16} className="text-cq-on-surface-variant animate-pulse" />
                ) : eligibility?.approval_eligible ? (
                  <ShieldCheck size={16} className="text-cq-secondary" />
                ) : (
                  <XCircle size={16} className="text-cq-warning" style={{ color: "#fbbf24" }} />
                )}
                <span className="text-[13px] font-semibold text-cq-on-surface">
                  {checkingEligibility
                    ? "Checking approval eligibility\u2026"
                    : eligibility?.approval_eligible
                      ? "Approval Eligible"
                      : "Not Approval Eligible"}
                </span>
              </div>
              {eligibility && !eligibility.approval_eligible && eligibility.reason && (
                <p className="text-[12.5px] text-cq-on-surface-variant mt-1.5 leading-relaxed">
                  {eligibility.reason}
                </p>
              )}
              {eligibility && (
                <p className="text-[12px] text-cq-on-surface-variant mt-1">
                  Policy: {eligibility.policy_passed ? "passed" : "failed"} · Risk: {eligibility.risk_level} ·
                  {" "}Device: {eligibility.device.revoked ? "revoked" : "ok"} ·
                  {" "}Session: {eligibility.session.valid ? "ok" : "invalid"}
                </p>
              )}
            </div>
          )}

          {result.lifecycle_state === "draft" ? (
            <Button
              variant="accent"
              accent="mint"
              full
              icon={ShieldCheck}
              loading={approving}
              disabled={checkingEligibility || (eligibility != null && !eligibility.approval_eligible)}
              onClick={handleApprove}
              className="mt-2"
            >
              Approve Intent
            </Button>
          ) : (
            <Button
              variant="accent"
              accent="mint"
              full
              iconRight={ArrowRight}
              onClick={() => navigate("encrypt", { intentCid: result.cid, intentId: result.intent_id })}
              className="mt-2"
            >
              Use this intent to encrypt
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
