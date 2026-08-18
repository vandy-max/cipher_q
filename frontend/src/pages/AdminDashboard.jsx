import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Users,
  ClipboardCheck,
  ShieldAlert,
  RefreshCcw,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import { Field, SelectField, TextField } from "../components/ui/Field";
import LifecyclePill from "../components/ui/LifecyclePill";
import {
  listUsers,
  updateUserRole,
  listIntents,
  transitionIntent,
  revokeDevice,
  unrevokeDevice,
  revokeSession,
} from "../services/api";

// Server-side enforced role model (see backend/api/rbac.py) — this is
// just the display list, never a source of authorization truth.
const USER_ROLES = ["USER_LEVEL_1", "USER_LEVEL_2"];

const TABS = [
  { id: "users", label: "Users & Roles", icon: Users },
  { id: "intents", label: "Intent Approval", icon: ClipboardCheck },
  { id: "devices", label: "Devices & Sessions", icon: ShieldAlert },
];

function Loading({ label }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center">
      <div className="relative w-11 h-11">
        <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
        <motion.div
          className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
        />
      </div>
      <p className="text-cq-body-md text-cq-on-surface-variant">{label}</p>
    </div>
  );
}

function EmptyState({ title, desc }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center text-center">
      <div className="text-[14.5px] font-semibold text-cq-on-surface">{title}</div>
      {desc && <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">{desc}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------
// Users & Roles
// ---------------------------------------------------------------------

function UsersPanel({ user }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingId, setSavingId] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setUsers(await listUsers());
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleRoleChange(id, role) {
    setSavingId(id);
    setError("");
    try {
      await updateUserRole(id, role);
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to update role");
    } finally {
      setSavingId(null);
    }
  }

  if (loading) return <Loading label="Loading users…" />;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Users & Roles</h2>
        <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>
          Refresh
        </Button>
      </div>
      <Alert type="error">{error}</Alert>
      {users.length === 0 ? (
        <EmptyState title="No users found" />
      ) : (
        <div className="overflow-x-auto -mx-2 sm:mx-0">
          <table className="w-full text-left border-collapse min-w-[520px]">
            <thead>
              <tr className="border-b border-cq-outline-variant/25">
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Username
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Email
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Role
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-cq-surface-container-high transition-colors">
                  <td className="py-3 px-3 text-[13.5px] text-cq-on-surface border-b border-cq-outline-variant/15">
                    {u.username}
                    {u.id === user?.userId && (
                      <span className="ml-2 text-[11px] uppercase tracking-wide text-cq-primary">you</span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-[13px] text-cq-on-surface-variant border-b border-cq-outline-variant/15">
                    {u.email}
                  </td>
                  <td className="py-3 px-3 border-b border-cq-outline-variant/15">
                    {u.role === "ADMIN" ? (
                      <span className="inline-flex items-center rounded-cq-md bg-cq-secondary-container/15 px-2.5 py-1.5 text-[13px] font-semibold text-cq-secondary">
                        ADMIN
                      </span>
                    ) : (
                      <SelectField
                        value={u.role}
                        disabled={savingId === u.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="!py-1.5 !text-[13px] max-w-[220px]"
                      >
                        {USER_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Intent Approval queue
// ---------------------------------------------------------------------

function IntentsPanel() {
  const [intents, setIntents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [filter, setFilter] = useState("draft");

  async function load(state, showLoading = true) {
    if (showLoading) setLoading(true);
    setError("");
    try {
      const nextIntents = await listIntents(state || undefined);
      setIntents(
        [...nextIntents].sort(
          (a, b) =>
            new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime() ||
            b.intent_id - a.intent_id
        )
      );
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load intents");
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  useEffect(() => {
    load(filter);

    // Keep the admin approval queue synchronized with intents created by
    // other users. Background refresh does not show a loading spinner,
    // so the queue remains usable while new drafts arrive.
    const refreshId = window.setInterval(() => load(filter, false), 3000);
    return () => window.clearInterval(refreshId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function handleTransition(intentId, target) {
    setBusyId(intentId);
    setError("");
    try {
      await transitionIntent(intentId, target, `admin dashboard: ${target}`);
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || `Failed to transition intent ${intentId}`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Approval</h2>
        <div className="flex items-center gap-2">
          <SelectField value={filter} onChange={(e) => setFilter(e.target.value)} className="!py-1.5 !text-[13px]">
            <option value="draft">Draft (pending review)</option>
            <option value="approved">Approved</option>
            <option value="used">Used</option>
            <option value="">All</option>
          </SelectField>
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
        </div>
      </div>
      <Alert type="error">{error}</Alert>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Separation of duties is enforced server-side: an intent's own creator can never approve
        it here — only a distinct USER_LEVEL_2/ADMIN reviewer can.
      </p>

      {loading ? (
        <Loading label="Loading intents…" />
      ) : intents.length === 0 ? (
        <EmptyState
          title="Nothing here"
          desc="No intents match this filter — try switching to Draft to see what's waiting for review."
        />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {intents.map((intent) => (
            <div
              key={intent.intent_id}
              className="rounded-cq-xl p-cq-stack-md bg-cq-surface-container-high border-l-2 border-cq-outline-variant/30"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[13.5px] font-bold text-cq-on-surface">Intent #{intent.intent_id}</span>
                <LifecyclePill state={intent.lifecycle_state} />
              </div>
              <div className="text-[12px] font-mono text-cq-on-surface-variant break-all mb-1">
                {intent.intent_hash.slice(0, 24)}…
              </div>
              <div className="text-[12.5px] text-cq-on-surface-variant mb-3">
                Created by user #{intent.created_by}
                {intent.created_at && <> · {new Date(intent.created_at).toLocaleString()}</>}
              </div>
              {intent.lifecycle_state === "draft" && (
                <div className="flex gap-2">
                  <Button
                    variant="brand"
                    size="sm"
                    icon={CheckCircle2}
                    loading={busyId === intent.intent_id}
                    onClick={() => handleTransition(intent.intent_id, "approved")}
                  >
                    Approve
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Devices & Sessions quick actions
// ---------------------------------------------------------------------

function DevicesPanel() {
  const [deviceId, setDeviceId] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function run(action, label) {
    setError("");
    setMessage("");
    try {
      await action();
      setMessage(label);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Action failed");
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Devices & Sessions</h2>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Revoking a device or session immediately invalidates the current cryptographic
        authorization state for it — any in-flight encrypt/decrypt request against it is
        rejected, and a fresh authentication is required to establish a new authorization state.
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
        <Field label="Device ID">
          <TextField value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="device-001" />
        </Field>
        <Field label="Session ID">
          <TextField value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="session-abc" />
        </Field>
      </div>
      <div className="flex flex-wrap gap-2 mt-2">
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!deviceId}
          onClick={() => run(() => revokeDevice(deviceId), `Device ${deviceId} revoked`)}
        >
          Revoke Device
        </Button>
        <Button
          variant="outline"
          size="sm"
          icon={CheckCircle2}
          disabled={!deviceId}
          onClick={() => run(() => unrevokeDevice(deviceId), `Device ${deviceId} unrevoked`)}
        >
          Unrevoke Device
        </Button>
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!sessionId}
          onClick={() => run(() => revokeSession(sessionId), `Session ${sessionId} revoked`)}
        >
          Revoke Session
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------

export default function AdminDashboard({ user }) {
  const [tab, setTab] = useState("users");

  return (
    <div>
      <PageHeader
        icon="admin_panel_settings"
        eyebrow="Administration"
        title="Admin Dashboard"
        description="Server-enforced role hierarchy: ADMIN, USER_LEVEL_2 (security officer/manager), USER_LEVEL_1 (user). Every action here is re-checked against the caller's role on the backend — this page only surfaces what the API already permits."
        right={
          <div className="inline-flex items-center gap-1.5 rounded-cq-md bg-cq-secondary-container/15 text-cq-secondary px-3 py-1.5 text-[12.5px] font-semibold">
            <ShieldCheck size={14} /> {user?.role || "—"}
          </div>
        }
      />

      <div className="flex items-center gap-1 mb-5 border-b border-cq-outline-variant/15 pb-1 overflow-x-auto">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={
                "inline-flex items-center gap-1.5 px-3.5 py-2 rounded-cq-md text-[13px] font-semibold whitespace-nowrap transition-colors " +
                (active
                  ? "bg-cq-primary-container/20 text-cq-primary"
                  : "text-cq-on-surface-variant hover:bg-cq-surface-container-highest hover:text-cq-on-surface")
              }
            >
              <Icon size={15} /> {t.label}
            </button>
          );
        })}
      </div>

      {tab === "users" && <UsersPanel user={user} />}
      {tab === "intents" && <IntentsPanel />}
      {tab === "devices" && <DevicesPanel />}
    </div>
  );
}