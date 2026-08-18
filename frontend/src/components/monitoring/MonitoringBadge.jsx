import { useEffect, useRef, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, ScanFace, ChevronDown } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import FaceAuthPanel from "../face/FaceAuthPanel";

const STATUS_META = {
  active: { label: "ACTIVE", color: "text-cq-primary", dot: "bg-cq-secondary", icon: ShieldCheck },
  warning: { label: "WARNING", color: "text-amber-400", dot: "bg-amber-400", icon: ShieldAlert },
  reauth_required: { label: "REAUTH REQUIRED", color: "text-amber-500", dot: "bg-amber-500", icon: ShieldAlert },
  revoked: { label: "REVOKED", color: "text-cq-error", dot: "bg-cq-error", icon: ShieldX },
};

// PHASE 4: COMPROMISED is a system-wide audit-integrity signal (a
// broken hash chain), distinct from — and takes visual priority over
// — this session's own ACTIVE/WARNING/REAUTH/REVOKED status.
const COMPROMISED_META = {
  label: "AUDIT INTEGRITY COMPROMISED",
  color: "text-purple-400",
  dot: "bg-purple-500",
  icon: ShieldX,
};

// PART 3 — explicit per-tick identity-check states, shown alongside
// (not instead of) the coarser Face/Liveness rows below.
const IDENTITY_STATE_META = {
  identity_confirmed: { label: "IDENTITY CONFIRMED", tone: "text-cq-primary" },
  identity_mismatch: { label: "IDENTITY MISMATCH", tone: "text-cq-error" },
  no_face: { label: "NO FACE DETECTED", tone: "text-cq-on-surface-variant" },
  liveness_uncertain: { label: "LIVENESS UNCERTAIN", tone: "text-amber-500" },
  camera_unavailable: { label: "CAMERA UNAVAILABLE", tone: "text-amber-500" },
};

const CAMERA_STATE_META = {
  idle: { label: "OFF", tone: "text-cq-on-surface-variant" },
  requesting: { label: "REQUESTING ACCESS", tone: "text-amber-500" },
  ready: { label: "ACTIVE", tone: "text-cq-primary" },
  unavailable: { label: "UNAVAILABLE", tone: "text-cq-error" },
};

function boolRow(label, ok, okLabel, badLabel) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-[12px] text-cq-on-surface-variant">{label}</span>
      <span className={`text-[12px] font-bold ${ok ? "text-cq-primary" : "text-cq-error"}`}>
        {ok ? okLabel : badLabel}
      </span>
    </div>
  );
}

/**
 * Persistent live monitoring indicator (sits in the Topbar). Shows:
 *   Monitoring: ACTIVE | WARNING | REAUTH REQUIRED | REVOKED
 * and, expanded, every derived security field the continuous
 * monitoring session tracks — Face, Liveness, Device, Session,
 * Intent, Risk, Authorization, Cryptography.
 */
export default function MonitoringBadge() {
  const { snapshot, isMonitoring, cameraState, connectionState, simulateFaceFailure, reauthenticate } = useMonitoringContext();
  const [open, setOpen] = useState(false);
  const [reauthOpen, setReauthOpen] = useState(false);
  const [reauthError, setReauthError] = useState("");
  const ref = useRef(null);

  useEffect(() => {
    function onDoc(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  if (!isMonitoring || !snapshot) {
    return (
      <div className="hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 text-cq-label-md text-cq-on-surface-variant">
        <div className="w-2 h-2 rounded-full bg-cq-outline" />
        <span className="font-label-md text-cq-label-md">MONITORING: OFF</span>
      </div>
    );
  }

  // PART 11 — a lost connection to the backend takes visual priority
  // over whatever status was last confirmed: we must not keep
  // implying ACTIVE off a stale snapshot the backend hasn't actually
  // re-confirmed recently.
  const connectionLostMeta = {
    label: "CONNECTION LOST",
    color: "text-amber-500",
    dot: "bg-amber-500",
    icon: ShieldAlert,
  };

  const meta = connectionState === "lost"
    ? connectionLostMeta
    : snapshot.security_state === "compromised"
      ? COMPROMISED_META
      : STATUS_META[snapshot.status] || STATUS_META.active;
  const Icon = meta.icon;
  const cryptoBlocked = snapshot.status === "revoked";
  const authValid = snapshot.current_authorization_state === "valid";
  const identityMeta = IDENTITY_STATE_META[snapshot.identity_state] || null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 ${meta.color}`}
      >
        <div className={`w-2 h-2 rounded-full ${meta.dot} ${snapshot.status === "active" ? "animate-pulse" : ""}`} />
        <span className="font-label-md text-cq-label-md">MONITORING: {meta.label}</span>
        <ChevronDown size={13} className="opacity-60" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-[300px] rounded-cq-md border border-cq-outline-variant/20 bg-cq-surface-container-low/95 backdrop-blur-xl shadow-cq-popover p-3.5 z-50">
          <div className="flex items-center gap-2 mb-2.5">
            <Icon size={16} className={meta.color} />
            <span className={`text-[13px] font-bold ${meta.color}`}>Monitoring: {meta.label}</span>
          </div>

          <div className="space-y-0.5 divide-y divide-cq-outline-variant/10">
            <div className="pb-1">
              {boolRow("Face", snapshot.face_present, "VERIFIED", "NOT DETECTED")}
              {boolRow("Liveness", snapshot.liveness, "ACTIVE", "FAILED")}
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Identity Check</span>
                <span className={`text-[12px] font-bold ${identityMeta?.tone || "text-cq-on-surface"}`}>
                  {identityMeta?.label || "—"}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Camera</span>
                <span className={`text-[12px] font-bold ${CAMERA_STATE_META[cameraState]?.tone || "text-cq-on-surface"}`}>
                  {CAMERA_STATE_META[cameraState]?.label || cameraState}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Connection</span>
                <span className={`text-[12px] font-bold ${connectionState === "lost" ? "text-amber-500" : "text-cq-primary"}`}>
                  {connectionState === "lost" ? "LOST" : "LIVE"}
                </span>
              </div>
            </div>
            <div className="py-1">
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Device</span>
                <span className="text-[12px] font-bold text-cq-on-surface truncate max-w-[150px]" title={snapshot.current_device}>
                  TRUSTED
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Session</span>
                <span className="text-[12px] font-bold text-cq-on-surface">
                  {authValid ? "ACTIVE" : "INVALID"}
                </span>
              </div>
              {snapshot.current_intent != null && (
                <div className="flex items-center justify-between py-1">
                  <span className="text-[12px] text-cq-on-surface-variant">Intent</span>
                  <span className="text-[12px] font-bold text-cq-on-surface uppercase">
                    {snapshot.current_lifecycle || "—"}
                  </span>
                </div>
              )}
            </div>
            <div className="py-1">
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Risk</span>
                <span className="text-[12px] font-bold text-cq-on-surface uppercase">{snapshot.current_risk}</span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Authorization</span>
                <span className={`text-[12px] font-bold ${authValid ? "text-cq-primary" : "text-cq-error"}`}>
                  {authValid ? "VALID" : "INVALID"}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Cryptography</span>
                <span className={`text-[12px] font-bold ${cryptoBlocked ? "text-cq-error" : "text-cq-primary"}`}>
                  {cryptoBlocked ? "BLOCKED" : "AVAILABLE"}
                </span>
              </div>
            </div>
          </div>

          {snapshot.warnings?.length > 0 && (
            <div className="mt-2.5 rounded-cq-sm bg-cq-error-container/10 px-2.5 py-2 text-[11.5px] text-cq-error leading-relaxed">
              {snapshot.warnings.join(" · ")}
            </div>
          )}

          <div className="mt-3 flex items-center gap-2">
            {(snapshot.status === "reauth_required" || snapshot.status === "revoked") && !reauthOpen && (
              <button
                onClick={() => {
                  setReauthError("");
                  setReauthOpen(true);
                }}
                className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-cq-sm bg-cq-primary text-cq-on-primary text-[12px] font-bold py-2"
              >
                <ScanFace size={13} /> Reauthenticate
              </button>
            )}
            {snapshot.status === "active" && (
              <button
                onClick={() => simulateFaceFailure(1)}
                className="flex-1 rounded-cq-sm border border-cq-outline-variant/30 text-cq-on-surface-variant text-[11.5px] font-semibold py-2 hover:bg-cq-surface-container-highest"
              >
                Simulate face-lost (demo)
              </button>
            )}
          </div>

          {reauthOpen && (
            <div className="mt-3">
              {reauthError && (
                <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                  {reauthError}
                </div>
              )}
              <FaceAuthPanel
                mode="verify"
                title="Reauthenticate"
                subtitle="Continuous monitoring detected a security event — verify your identity to restore authorization."
                onSuccess={async ({ descriptor }) => {
                  try {
                    await reauthenticate(descriptor);
                    setReauthOpen(false);
                    setOpen(false);
                  } catch (err) {
                    setReauthError(err.message || "Reauthentication failed");
                  }
                }}
                onCancel={() => setReauthOpen(false)}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
