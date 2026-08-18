import { useEffect, useMemo, useState } from "react";
import {
  FilePlus2,
  Atom,
  Lock,
  KeyRound,
  ShieldCheck,
  ScrollText,
  ArrowRight,
  ListChecks,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  Cpu,
} from "lucide-react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { motion } from "framer-motion";
import BentoCard from "../components/ui/BentoCard";
import { listAuditLogs, verifyAuditChain, quantumBackendInfo, listPolicies } from "../services/api";

const QUICK_ACTIONS = [
  { id: "create-intent", icon: FilePlus2, label: "Create Intent" },
  { id: "bb84", icon: Atom, label: "Quantum Center" },
  { id: "encrypt", icon: Lock, label: "Encrypt" },
  { id: "decrypt", icon: KeyRound, label: "Decrypt" },
];

const REJECT_PATTERN = /reject|denied|fail|forbidden|abort|invalid/i;
const SUCCESS_PATTERN = /success|ok|approved|granted/i;

// Recharts takes literal colors, not Tailwind classes — these mirror the
// cq-* tokens defined in tailwind.config.js / globals.css.
const CQ = {
  primary: "#b8c3ff",
  primaryContainer: "#2e5bff",
  secondary: "#63f7ff",
  tertiaryContainer: "#a03ad3",
  error: "#ffb4ab",
  outline: "#8e90a2",
  gridLine: "rgba(255,255,255,0.06)",
};

export default function Dashboard({ navigate, user }) {
  const [logs, setLogs] = useState(null);
  const [chain, setChain] = useState(null);
  const [quantum, setQuantum] = useState(null);
  const [policies, setPolicies] = useState(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      listAuditLogs().catch(() => []),
      verifyAuditChain().catch(() => null),
      quantumBackendInfo().catch(() => ({ qiskit_available: false })),
      listPolicies().catch(() => []),
    ]).then(([l, c, q, p]) => {
      if (cancelled) return;
      setLogs(l);
      setChain(c);
      setQuantum(q);
      setPolicies(p);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const loading = logs === null;

  const stats = useMemo(() => {
    if (!logs) return null;
    const success = logs.filter((l) => SUCCESS_PATTERN.test(l.result)).length;
    const rejected = logs.filter((l) => REJECT_PATTERN.test(l.result)).length;
    const encryptCount = logs.filter((l) => /encrypt/i.test(l.action) && !/decrypt/i.test(l.action)).length;
    const decryptCount = logs.filter((l) => /decrypt/i.test(l.action)).length;
    const last24h = logs.filter((l) => Date.now() - new Date(l.timestamp).getTime() < 86400000).length;

    // Events per day for the last 7 days — grouped from real timestamps.
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days.push({ key, label: d.toLocaleDateString(undefined, { weekday: "short" }), events: 0 });
    }
    logs.forEach((l) => {
      const key = new Date(l.timestamp).toISOString().slice(0, 10);
      const bucket = days.find((d) => d.key === key);
      if (bucket) bucket.events += 1;
    });

    // Action breakdown
    const actionMap = {};
    logs.forEach((l) => {
      actionMap[l.action] = (actionMap[l.action] || 0) + 1;
    });
    const actionBreakdown = Object.entries(actionMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({ name, count }));

    return { success, rejected, encryptCount, decryptCount, last24h, days, actionBreakdown, total: logs.length };
  }, [logs]);

  const recent = (logs || []).slice(0, 6);

  return (
    <div>
      {/* Status Banner & Hero — mirrors dashboard_1/code.html's hero panel.
          Every value here is derived from real audit/quantum/policy data
          fetched above; nothing is fabricated (no fake node counts). */}
      <div className="relative mb-cq-stack-lg overflow-hidden rounded-cq-xl bg-cq-surface-container-low p-cq-margin-mobile sm:p-cq-margin-desktop">
        {!loading && (
          <div className="absolute top-4 right-4 sm:top-cq-stack-md sm:right-cq-stack-md">
            <div className="flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-secondary/10 border border-cq-secondary/20 shadow-cq-glow-secondary">
              <div className="w-2 h-2 rounded-full bg-cq-secondary animate-pulse shadow-cq-dot-secondary" />
              <span className="font-label-md text-cq-label-md text-cq-secondary tracking-widest uppercase">
                {quantum?.qiskit_available ? "Quantum Fabric Active" : "Quantum Fabric Offline"} · {stats.total} Logged Operations
              </span>
            </div>
          </div>
        )}
        <div className="relative z-10 max-w-3xl">
          <div className="flex items-center gap-cq-stack-sm mb-cq-stack-sm">
            <span className="text-cq-primary font-mono text-cq-label-md tracking-[0.2em] uppercase">Security Protocol v4.0</span>
            <div className="h-px w-12 bg-cq-primary/30" />
          </div>
          <h1 className="font-display-lg text-cq-display-lg text-cq-on-surface mb-cq-stack-md tracking-tighter text-[32px] sm:text-cq-display-lg">
            System Integrity:{" "}
            <span className={chain?.valid === false ? "text-cq-error" : "text-cq-secondary"}>
              {loading ? "Checking…" : chain?.valid === false ? "Compromised" : "Nominal"}
            </span>
          </h1>
          <p className="font-body-lg text-cq-body-lg text-cq-on-surface-variant leading-relaxed opacity-80">
            Welcome back, <span className="text-cq-on-surface font-semibold">{user?.username || "operator"}</span>. Operating on
            Intent-Bound Quantum Cryptography — every cryptographic operation is tied to a verified business intent, ensuring key
            distribution only occurs within validated logical contexts.
          </p>
        </div>
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 mb-6">
        {QUICK_ACTIONS.map((a) => (
          <button
            key={a.id}
            onClick={() => navigate(a.id)}
            className="group flex items-center gap-3 rounded-cq-lg bg-cq-surface-container px-4 py-3.5 text-left hover:bg-cq-surface-container-high transition-colors duration-200"
          >
            <span className="inline-flex items-center justify-center w-9 h-9 rounded-cq-md bg-cq-primary-container/20 text-cq-primary shrink-0">
              <a.icon size={17} />
            </span>
            <span className="text-[13px] font-semibold text-cq-on-surface leading-tight">{a.label}</span>
            <ArrowRight size={14} className="ml-auto text-cq-outline opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
          </button>
        ))}
      </div>

      {loading ? (
        <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center">
          <div className="relative w-11 h-11">
            <motion.div
              className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20"
            />
            <motion.div
              className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
            />
          </div>
          <p className="text-cq-body-md text-cq-on-surface-variant">Assembling security overview…</p>
        </div>
      ) : (
        <>
          {/* KPI row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 mb-6">
            <BentoCard icon={ListChecks} label="Total Events" value={stats.total} />
            <BentoCard icon={CheckCircle2} label="Successful" value={stats.success} trend={stats.total ? `${Math.round((stats.success / stats.total) * 100)}%` : undefined} />
            <BentoCard icon={XCircle} label="Rejected" value={stats.rejected} trendTone="muted" trend={stats.total ? `${Math.round((stats.rejected / stats.total) * 100)}%` : undefined} />
            <BentoCard icon={ShieldAlert} label="Last 24h" value={stats.last24h} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
            {/* Activity chart */}
            <div className="xl:col-span-2 bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <SectionHeading desc="Audit events recorded over the last 7 days.">Activity</SectionHeading>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats.days}>
                  <defs>
                    <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CQ.primary} stopOpacity={0.35} />
                      <stop offset="100%" stopColor={CQ.primary} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={CQ.gridLine} vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 12, fill: CQ.outline }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 12, fill: CQ.outline }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      borderRadius: 12,
                      border: "1px solid rgba(255,255,255,0.08)",
                      background: "#1d1f29",
                      color: "#e2e1ef",
                      fontSize: 13,
                    }}
                  />
                  <Area type="monotone" dataKey="events" stroke={CQ.primary} strokeWidth={2.5} fill="url(#activityFill)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* System status */}
            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <SectionHeading>System Status</SectionHeading>
              <div className="space-y-3">
                <StatusRow
                  icon={ShieldCheck}
                  label="Audit Chain"
                  ok={chain?.valid !== false}
                  okText="Intact"
                  badText="Compromised"
                />
                <StatusRow
                  icon={Atom}
                  label="Quantum Backend"
                  ok={!!quantum?.qiskit_available}
                  okText={quantum?.simulator || "Online"}
                  badText="Unavailable"
                />
                <StatusRow
                  icon={ScrollText}
                  label="Active Policies"
                  ok={(policies || []).some((p) => p.active)}
                  okText={`${(policies || []).filter((p) => p.active).length} active`}
                  badText="None active"
                />
                <StatusRow icon={Cpu} label="Encrypt Events" ok value={stats.encryptCount} />
                <StatusRow icon={KeyRound} label="Decrypt Events" ok value={stats.decryptCount} />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
            {/* Action breakdown */}
            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <SectionHeading desc="Most frequent actions in the audit log.">Action Breakdown</SectionHeading>
              {stats.actionBreakdown.length === 0 ? (
                <EmptyPanel title="No events yet" />
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={stats.actionBreakdown} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={CQ.gridLine} />
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12, fill: CQ.outline }} />
                    <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 11.5, fill: "#c4c5d9" }} />
                    <Tooltip
                      contentStyle={{
                        borderRadius: 12,
                        border: "1px solid rgba(255,255,255,0.08)",
                        background: "#1d1f29",
                        color: "#e2e1ef",
                        fontSize: 13,
                      }}
                    />
                    <Bar dataKey="count" fill={CQ.tertiaryContainer} radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Recent activity */}
            <div className="xl:col-span-2 bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center justify-between mb-4">
                <SectionHeading desc="Latest entries from the tamper-evident audit chain.">Recent Activity</SectionHeading>
                <button
                  onClick={() => navigate("audit")}
                  className="flex items-center gap-1.5 text-[13px] font-semibold text-cq-primary hover:text-cq-on-surface transition-colors"
                >
                  View all
                  <ArrowRight size={14} />
                </button>
              </div>
              {recent.length === 0 ? (
                <EmptyPanel title="No recent activity" />
              ) : (
                <div className="divide-y divide-cq-outline-variant/15">
                  {recent.map((l, i) => {
                    const ok = SUCCESS_PATTERN.test(l.result);
                    return (
                      <div key={i} className="flex items-center gap-3 py-2.5">
                        <span
                          className={
                            "inline-flex items-center justify-center w-8 h-8 rounded-cq-md shrink-0 " +
                            (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
                          }
                        >
                          {ok ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="text-[13.5px] font-semibold text-cq-on-surface truncate">{l.action}</div>
                          <div className="text-[12px] text-cq-on-surface-variant">{new Date(l.timestamp).toLocaleString()}</div>
                        </div>
                        <span
                          className={
                            "text-[11px] font-semibold px-2 py-1 rounded-full " +
                            (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
                          }
                        >
                          {l.result}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SectionHeading({ children, desc }) {
  return (
    <div className="mb-4">
      <h2 className="text-[16px] font-bold text-cq-on-surface">{children}</h2>
      {desc && <p className="text-[13px] text-cq-on-surface-variant mt-0.5">{desc}</p>}
    </div>
  );
}

function EmptyPanel({ title }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6">
      <div className="text-[14.5px] font-semibold text-cq-on-surface">{title}</div>
    </div>
  );
}

function StatusRow({ icon: Icon, label, ok, okText, badText, value }) {
  return (
    <div className="flex items-center justify-between">
      <span className="inline-flex items-center gap-2 text-[13px] font-medium text-cq-on-surface-variant">
        <Icon size={15} className="text-cq-outline" />
        {label}
      </span>
      {value !== undefined ? (
        <span className="text-[13px] font-bold text-cq-on-surface">{value}</span>
      ) : (
        <span
          className={
            "text-[11px] font-semibold px-2 py-1 rounded-full " +
            (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
          }
        >
          {ok ? okText : badText}
        </span>
      )}
    </div>
  );
}
