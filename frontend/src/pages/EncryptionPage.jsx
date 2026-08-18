import { useMemo, useState } from "react";
import { Lock, ArrowRight, CheckCircle2 } from "lucide-react";
import CopyBox from "../components/CopyBox";
import { WorkflowStepper, TaskChecklist } from "../components/ui/WorkflowStepper";
import { Field, TextField, TextAreaField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { encrypt, createIntent, transitionIntent } from "../services/api";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import MonitoringBlockedBanner from "../components/monitoring/MonitoringBlockedBanner";

function toBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

const OPERATIONS = ["encrypt", "decrypt", "read", "write", "share", "revoke"];
const STEPS = ["Intent Context", "Quantum Key", "Encrypt"];

function isoLocalToUtc(value) {
  if (!value) return "";
  return new Date(value).toISOString();
}

export default function EncryptionPage({ navigate, shared }) {
  const [quantumKeyHex, setQuantumKeyHex] = useState(shared?.quantumKeyHex || "");
  const [plaintext, setPlaintext] = useState("");
  const [cidForm, setCidForm] = useState(() => {
    const c = shared?.intentCid;
    return {
      sender: c?.sender || "",
      receiver: c?.receiver || "",
      purpose: c?.purpose || "",
      resource: c?.resource || "",
      operation: c?.operation || "decrypt",
      device_id: c?.device_id || "",
      session_id: c?.session_id || "",
      valid_from: "",
      valid_until: "",
    };
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(null); // "deriving" | "encrypting" | null
  const [showFaceGate, setShowFaceGate] = useState(false);
  const [pendingCid, setPendingCid] = useState(null);

  const set = (key) => (e) => setCidForm((f) => ({ ...f, [key]: e.target.value }));

  const intentComplete = shared?.intentCid
    ? true
    : Boolean(
        cidForm.sender &&
          cidForm.receiver &&
          cidForm.purpose &&
          cidForm.resource &&
          cidForm.device_id &&
          cidForm.session_id &&
          cidForm.valid_from &&
          cidForm.valid_until
      );
  const keyComplete = Boolean(quantumKeyHex);
  const activeStep = result ? 3 : !intentComplete ? 0 : !keyComplete ? 1 : 2;

  function handleSubmit(e) {
    e.preventDefault();
    setError("");
    const cid = shared?.intentCid
      ? shared.intentCid
      : {
          ...cidForm,
          valid_from: isoLocalToUtc(cidForm.valid_from),
          valid_until: isoLocalToUtc(cidForm.valid_until),
        };
    // Before encryption starts, the user must pass live face
    // verification — this opens the reusable Face Authentication
    // panel; the actual /api/encrypt call only fires from its
    // onSuccess handler below.
    setPendingCid(cid);
    setShowFaceGate(true);
  }

  async function runEncrypt(faceDescriptor) {
    setShowFaceGate(false);
    setError("");
    setLoading(true);
    setStage("deriving");
    try {
      let intentId = shared?.intentId;
      if (!intentId) {
        // No pre-created (and approved) intent was handed off from
        // Create Intent — create one now and approve it, so this
        // page still works as a one-shot flow. The intent still goes
        // through the real Draft -> Approved transition; nothing
        // here writes lifecycle state directly.
        const created = await createIntent(pendingCid, "encryption");
        await transitionIntent(created.intent_id, "approved", "approved for encryption");
        intentId = created.intent_id;
      }
      // Brief staged reveal — the real work happens in one backend call,
      // this just narrates the pipeline documented for this endpoint.
      await new Promise((r) => setTimeout(r, 350));
      setStage("encrypting");
      const response = await encrypt(intentId, pendingCid, toBase64(plaintext), quantumKeyHex, faceDescriptor);
      setResult({ ...response, cid: pendingCid });
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Encryption failed");
    } finally {
      setLoading(false);
      setStage(null);
    }
  }

  const checklistItems = useMemo(
    () => [
      { label: "Canonicalize intent context", status: stage ? "done" : "pending" },
      { label: "Derive key via HKDF (quantum key + intent hash)", status: stage === "deriving" ? "active" : stage === "encrypting" ? "done" : "pending" },
      { label: "AES-256-GCM encrypt", status: stage === "encrypting" ? "active" : "pending" },
    ],
    [stage]
  );

  return (
    <div>
      <PageHeader
        icon="lock"
        eyebrow="Encryption Pipeline"
        title="Encryption"
        description="HKDF derives an intent-bound key from the quantum key plus the intent hash, then AES-256-GCM seals the payload. No key ever touches ciphertext without a validated intent binding."
      />
      <MonitoringBlockedBanner />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <WorkflowStepper steps={STEPS} activeIndex={activeStep} />
        <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">Encrypt a Message</h2>
        <form onSubmit={handleSubmit}>
          <Field label="Quantum Key (hex)" hint="from Quantum Center">
            <TextField
              mono
              value={quantumKeyHex}
              onChange={(e) => setQuantumKeyHex(e.target.value)}
              placeholder="Generate one on the Quantum Center page"
              required
            />
          </Field>

          <Field label="Plaintext">
            <TextAreaField rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} required />
          </Field>

          {shared?.intentCid ? (
            <div className="rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] text-cq-on-surface-variant mb-4">
              Using intent from Create Intent: <code className="font-mono text-cq-on-surface">{shared.intentCid.purpose}</code>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
                <Field label="Sender">
                  <TextField value={cidForm.sender} onChange={set("sender")} required />
                </Field>
                <Field label="Receiver">
                  <TextField value={cidForm.receiver} onChange={set("receiver")} required />
                </Field>
              </div>
              <Field label="Purpose">
                <TextField value={cidForm.purpose} onChange={set("purpose")} required />
              </Field>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
                <Field label="Resource">
                  <TextField value={cidForm.resource} onChange={set("resource")} required />
                </Field>
                <Field label="Operation">
                  <SelectField value={cidForm.operation} onChange={set("operation")}>
                    {OPERATIONS.map((op) => (
                      <option key={op} value={op}>{op}</option>
                    ))}
                  </SelectField>
                </Field>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
                <Field label="Device ID">
                  <TextField value={cidForm.device_id} onChange={set("device_id")} required />
                </Field>
                <Field label="Session ID">
                  <TextField value={cidForm.session_id} onChange={set("session_id")} required />
                </Field>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
                <Field label="Valid From">
                  <TextField type="datetime-local" value={cidForm.valid_from} onChange={set("valid_from")} required />
                </Field>
                <Field label="Valid Until">
                  <TextField type="datetime-local" value={cidForm.valid_until} onChange={set("valid_until")} required />
                </Field>
              </div>
            </>
          )}

          <Alert type="error">{error}</Alert>

          {showFaceGate ? (
            <FaceAuthPanel
              mode="verify"
              title="Verify your identity to encrypt"
              subtitle="A live face check runs before every encryption request."
              onSuccess={({ descriptor }) => runEncrypt(descriptor)}
              onCancel={() => setShowFaceGate(false)}
            />
          ) : loading ? (
            <TaskChecklist items={checklistItems} />
          ) : (
            <Button type="submit" variant="accent" accent="mint" full icon={Lock}>
              Encrypt
            </Button>
          )}
        </form>
      </div>

      {result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Ciphertext Stored</h2>
          </div>
          <p className="text-[13px] text-cq-on-surface-variant mb-4">
            The AES key itself was never stored — only ciphertext, nonce, tag, and the intent hash.
          </p>
          <CopyBox label="Record ID" value={String(result.record_id)} />
          <CopyBox label="Intent Hash" value={result.intent_hash} />
          <CopyBox label="Ciphertext (hex)" value={result.ciphertext_hex} />
          <CopyBox label="Nonce (hex)" value={result.nonce_hex} />
          <CopyBox label="Auth Tag (hex)" value={result.auth_tag_hex} />
          <div className="mt-4 rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] leading-relaxed text-cq-on-surface-variant">
            Decryption has to rederive the key from scratch — from the same quantum key and an
            intent context that canonicalizes to the same hash.
          </div>
          <Button
            variant="accent"
            accent="peach"
            full
            iconRight={ArrowRight}
            className="mt-4"
            onClick={() =>
              navigate("decrypt", {
                recordId: result.record_id,
                lastCid: result.cid,
                lastQuantumKeyHex: quantumKeyHex,
              })
            }
          >
            Try decrypting this record
          </Button>
        </div>
      )}
    </div>
  );
}
