import { useEffect, useState } from "react";
import { ScrollText, Trash2 } from "lucide-react";
import { motion } from "framer-motion";
import { Field, TextField, SelectField, CheckboxField, TextAreaField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { createPolicy, deletePolicy, listPolicies } from "../services/api";

const RULE_TYPES = [
  "allowed_operation",
  "allowed_device",
  "session_timeout",
  "validity_period",
  "resource_matching",
  "role_matching",
];

export default function PolicyManagementPage() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [name, setName] = useState("");
  const [ruleType, setRuleType] = useState(RULE_TYPES[0]);
  const [configText, setConfigText] = useState("{}");
  const [active, setActive] = useState(true);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setPolicies(await listPolicies());
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    setError("");
    let config;
    try {
      config = JSON.parse(configText || "{}");
    } catch {
      setError("Config must be valid JSON");
      return;
    }
    try {
      await createPolicy(name, ruleType, config, active);
      setName("");
      setConfigText("{}");
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to create policy");
    }
  }

  async function handleDelete(id) {
    try {
      await deletePolicy(id);
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to delete policy");
    }
  }

  return (
    <div>
      <PageHeader
        icon="gavel"
        eyebrow="Policy Engine"
        title="Policy Engine"
        description="Configure the rules the policy engine evaluates before any key derivation. Every intent is checked against the active rule set before it can bind to a quantum key."
      />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">New Policy</h2>
        <form onSubmit={handleCreate}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Name">
              <TextField value={name} onChange={(e) => setName(e.target.value)} required />
            </Field>
            <Field label="Rule Type">
              <SelectField value={ruleType} onChange={(e) => setRuleType(e.target.value)}>
                {RULE_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </SelectField>
            </Field>
          </div>
          <Field label="Config (JSON)">
            <TextAreaField
              mono
              rows={3}
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder='e.g. {"allowed_devices": ["device-001"]}'
              className="font-mono text-[13px]"
            />
          </Field>
          <Field>
            <CheckboxField checked={active} onChange={setActive} label="Active" />
          </Field>

          <Alert type="error">{error}</Alert>

          <Button type="submit" variant="brand" full icon={ScrollText}>
            Add Policy
          </Button>
        </form>
      </div>

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
          <p className="text-cq-body-md text-cq-on-surface-variant">Loading policies…</p>
        </div>
      ) : policies.length === 0 ? (
        <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center text-center mt-6">
          <div className="text-[14.5px] font-semibold text-cq-on-surface">No policies configured yet</div>
          <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">
            Add your first rule above to start governing the platform.
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-5 mt-6">
          {policies.map((p) => (
            <div
              key={p.id}
              className={
                "rounded-cq-xl p-cq-stack-lg bg-cq-surface-container border-l-2 " +
                (p.active ? "border-cq-secondary" : "border-cq-outline-variant/40")
              }
            >
              <div className="text-[15px] font-bold text-cq-on-surface mb-1">{p.name}</div>
              <div className="text-[12.5px] font-mono text-cq-on-surface-variant">{p.rule_type}</div>
              <pre className="mt-3 rounded-cq-md bg-cq-surface-container-high p-3 text-[12px] font-mono text-cq-on-surface-variant whitespace-pre-wrap break-words max-h-40 overflow-auto">
                {JSON.stringify(p.config, null, 2)}
              </pre>
              <div className="mt-4 flex items-center justify-between">
                <span
                  className={
                    "text-[11.5px] font-semibold uppercase tracking-wide " +
                    (p.active ? "text-cq-secondary" : "text-cq-on-surface-variant")
                  }
                >
                  {p.active ? "active" : "inactive"}
                </span>
                <Button variant="ghost" size="sm" icon={Trash2} onClick={() => handleDelete(p.id)}>
                  Delete
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
