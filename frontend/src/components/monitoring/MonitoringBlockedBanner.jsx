import { ShieldX } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";

/**
 * Continuous monitoring can revoke authorization between page loads —
 * the server already rejects the actual encrypt/decrypt call in that
 * case (via the same SessionRepository the monitoring loop revokes
 * through), but showing it here too means the user doesn't have to
 * submit a form just to find out.
 */
export default function MonitoringBlockedBanner() {
  let ctx;
  try {
    ctx = useMonitoringContext();
  } catch {
    return null; // rendered outside a MonitoringProvider — nothing to show
  }
  const { snapshot } = ctx;
  if (!snapshot || snapshot.status !== "revoked") return null;

  return (
    <div className="mb-5 flex items-start gap-3 rounded-cq-lg border border-cq-error/30 bg-cq-error-container/10 px-4 py-3.5">
      <ShieldX size={18} className="text-cq-error shrink-0 mt-0.5" />
      <div>
        <div className="text-[13.5px] font-bold text-cq-error">Cryptography: BLOCKED</div>
        <div className="text-[12.5px] text-cq-on-surface-variant mt-0.5">
          Continuous monitoring invalidated this session's authorization
          {snapshot.warnings?.length ? `: ${snapshot.warnings.join(" · ")}` : "."} Reauthenticate
          from the monitoring badge above to restore access.
        </div>
      </div>
    </div>
  );
}
