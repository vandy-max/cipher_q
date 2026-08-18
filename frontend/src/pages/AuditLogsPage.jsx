import { useEffect, useMemo, useState } from "react";
import { RefreshCcw, ShieldAlert, Download, ListChecks, CheckCircle2, XCircle } from "lucide-react";
import { motion } from "framer-motion";
import BentoCard from "../components/ui/BentoCard";
import DataTable from "../components/ui/DataTable";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { listAuditLogs, verifyAuditChain } from "../services/api";

function Pill({ ok, children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap " +
        (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
      }
    >
      {ok ? <CheckCircle2 size={13} strokeWidth={2.5} /> : <XCircle size={13} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

function exportCsv(logs) {
  const header = ["timestamp", "user_id", "action", "result", "intent_hash", "current_log_hash"];
  const rows = logs.map((l) => header.map((h) => JSON.stringify(l[h] ?? "")).join(","));
  const csv = [header.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ibqc-audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [verification, setVerification] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [logsResponse, verifyResponse] = await Promise.all([
        listAuditLogs(),
        verifyAuditChain(),
      ]);
      setLogs(logsResponse);
      setVerification(verifyResponse);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const stats = useMemo(() => {
    const success = logs.filter((l) => /success|ok|approved|granted/i.test(l.result)).length;
    const rejected = logs.length - success;
    const last24h = logs.filter((l) => Date.now() - new Date(l.timestamp).getTime() < 86400000).length;
    return { total: logs.length, success, rejected, last24h };
  }, [logs]);

  const columns = [
    {
      key: "timestamp",
      label: "Timestamp",
      sortable: true,
      mono: true,
      render: (r) =>
        new Date(r.timestamp).toLocaleString(undefined, {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: true,
        }),
    },
    { key: "user_id", label: "User", sortable: true, render: (r) => r.user_id ?? "—" },
    { key: "action", label: "Action", sortable: true },
    {
      key: "result",
      label: "Result",
      sortable: true,
      render: (r) => <Pill ok={/success|ok|approved|granted/i.test(r.result)}>{r.result}</Pill>,
    },
    {
      key: "intent_hash",
      label: "Intent Hash",
      mono: true,
      render: (r) => (r.intent_hash ? r.intent_hash.slice(0, 12) + "…" : "—"),
    },
    {
      key: "current_log_hash",
      label: "Log Hash",
      mono: true,
      render: (r) => r.current_log_hash.slice(0, 12) + "…",
    },
  ];

  const rows = logs.map((l, i) => ({ ...l, id: i }));

  return (
    <div>
      <PageHeader
        icon="verified_user"
        eyebrow="Forensic Integrity Verified"
        title="Audit Trail"
        description="The CipherQ immutable ledger uses a hash-chained architecture. Every administrative action and intent modification is cryptographically linked to the preceding entry, giving mathematical proof of non-repudiation."
        right={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" icon={Download} onClick={() => exportCsv(logs)} disabled={!logs.length}>
              Export CSV
            </Button>
            <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>
              Refresh
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 mb-6">
        <BentoCard icon={ListChecks} label="Total Events" value={stats.total} />
        <BentoCard icon={CheckCircle2} label="Successful" value={stats.success} />
        <BentoCard icon={XCircle} label="Rejected" value={stats.rejected} trendTone="muted" />
        <BentoCard icon={ShieldAlert} label="Last 24h" value={stats.last24h} />
      </div>

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="flex items-center justify-between flex-wrap gap-3">
          {verification && (
            <Pill ok={verification.valid}>
              {verification.valid
                ? "Hash chain intact — no tampering detected"
                : `Tampering detected at entry ${verification.first_invalid_index}`}
            </Pill>
          )}
        </div>
        {verification && !verification.valid && (
          <div className="mt-3.5 flex items-start gap-2.5 rounded-cq-md bg-cq-error-container/15 px-4 py-3 text-[13px] text-cq-error">
            <ShieldAlert size={16} className="shrink-0 mt-0.5" />
            {verification.reason}
          </div>
        )}
      </div>

      <Alert type="error">{error}</Alert>

      {loading ? (
        <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center mt-6">
          <div className="relative w-11 h-11">
            <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
            <motion.div
              className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
            />
          </div>
          <p className="text-cq-body-md text-cq-on-surface-variant">Loading audit trail…</p>
        </div>
      ) : (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <DataTable
            columns={columns}
            rows={rows}
            searchKeys={["action", "result", "user_id", "intent_hash"]}
            searchPlaceholder="Search action, result, user, or hash…"
            emptyTitle="No audit entries yet"
            emptyDesc="Actions across the platform will appear here as they occur."
          />
        </div>
      )}
    </div>
  );
}