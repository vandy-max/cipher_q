import clsx from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronsLeft, ChevronsRight, X } from "lucide-react";

// Flat nav list — mirrors the canonical Stitch sidebar markup shared by
// intent_management_1, decryption_verification_1, policy_engine_1 and
// audit_trail_1/code.html (Material Symbols icon + uppercase label-md,
// rounded-lg row, active = primary-container/20 fill + right accent bar).
// `face-test` has no Stitch mockup (IBQC-only feature); it's appended
// after Decryption with the closest-matching Material Symbol so no
// existing route/feature is dropped.
const NAV = [
  { id: "dashboard", label: "Dashboard", icon: "grid_view" },
  { id: "bb84", label: "QKD Simulation", icon: "hub" },
  { id: "create-intent", label: "Intent Management", icon: "center_focus_strong" },
  { id: "intent-history", label: "Intent Lifecycle", icon: "history" },
  { id: "encrypt", label: "Encryption", icon: "lock" },
  { id: "decrypt", label: "Decryption", icon: "lock_open" },
  { id: "face-test", label: "Face Auth", icon: "face" },
  { id: "policies", label: "Policy Engine", icon: "gavel" },
  { id: "visualize", label: "Risk Analysis", icon: "radar" },
  { id: "audit", label: "Audit Trail", icon: "policy" },
];

// Admin-only nav entries: shown only when the authenticated user's
// role permits it (server-side enforcement lives in the backend
// RBAC/rbac.py — this is purely a UI convenience, never the actual
// authorization boundary).
const ADMIN_NAV = [{ id: "admin", label: "Admin Dashboard", icon: "admin_panel_settings" }];
const ADMIN_ROLES = new Set(["ADMIN", "USER_LEVEL_2"]);

function NavItem({ item, currentPage, navigate, collapsed, onNavigate }) {
  const active = currentPage === item.id;
  return (
    <button
      onClick={() => {
        navigate(item.id);
        onNavigate?.();
      }}
      title={collapsed ? item.label : undefined}
      className={clsx(
        "group relative w-full flex items-center px-cq-stack-md py-3 rounded-cq-md transition-all",
        collapsed && "justify-center px-0",
        active
          ? "bg-cq-primary-container/20 text-cq-primary font-bold"
          : "text-cq-on-surface-variant hover:bg-cq-surface-container-highest hover:text-cq-on-surface"
      )}
    >
      {active && (
        <motion.span
          layoutId="sidebar-active-bar"
          className="absolute right-0 top-1.5 bottom-1.5 w-[2px] rounded-full bg-cq-primary"
        />
      )}
      <span className={clsx("material-symbols-outlined text-[20px]", !collapsed && "mr-3")}>{item.icon}</span>
      {!collapsed && (
        <span className="font-label-md text-cq-label-md uppercase tracking-widest truncate">{item.label}</span>
      )}
    </button>
  );
}

export default function Sidebar({ currentPage, navigate, collapsed, setCollapsed, mobileOpen, setMobileOpen, user }) {
  const navItems = ADMIN_ROLES.has(user?.role) ? [...NAV, ...ADMIN_NAV] : NAV;
  const content = (
    <div className="cq-glass-sidebar flex h-full flex-col pt-cq-stack-lg pb-cq-stack-lg">
      {/* Brand */}
      <div className={clsx("flex items-center gap-cq-stack-sm px-cq-stack-lg mb-10", collapsed && "justify-center px-0")}>
        <div className="flex items-center justify-center w-8 h-8 rounded-cq-md bg-cq-primary-container shadow-cq-glow-primary shrink-0">
          <span className="material-symbols-outlined text-[18px] text-cq-on-primary-container">shield_lock</span>
        </div>
        {!collapsed && (
          <span className="font-headline-md text-cq-headline-md text-cq-on-surface tracking-tight">CipherQ</span>
        )}
        <button
          className="ml-auto hidden lg:inline-flex items-center justify-center w-7 h-7 rounded-cq-sm text-cq-on-surface-variant hover:bg-cq-surface-container-highest transition-colors"
          onClick={() => setCollapsed((v) => !v)}
        >
          {collapsed ? <ChevronsRight size={15} /> : <ChevronsLeft size={15} />}
        </button>
        <button
          className="ml-auto lg:hidden inline-flex items-center justify-center w-7 h-7 rounded-cq-sm text-cq-on-surface-variant hover:bg-cq-surface-container-highest"
          onClick={() => setMobileOpen(false)}
        >
          <X size={16} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto cq-no-scrollbar px-cq-stack-md flex flex-col gap-1">
        {navItems.map((item) => (
          <NavItem
            key={item.id}
            item={item}
            currentPage={currentPage}
            navigate={navigate}
            collapsed={collapsed}
            onNavigate={() => setMobileOpen(false)}
          />
        ))}
      </nav>

      {/* Settings, pinned bottom — matches the `mt-auto` settings link in every Stitch sidebar */}
      <div className="mt-auto border-t border-cq-outline-variant/20 pt-1 px-cq-stack-md">
        <NavItem
          item={{ id: "settings", label: "Settings", icon: "settings" }}
          currentPage={currentPage}
          navigate={navigate}
          collapsed={collapsed}
          onNavigate={() => setMobileOpen(false)}
        />
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop sidebar — Stitch spec is a fixed 280px rail; kept collapsible
          (existing IBQC feature) rather than removed, per "do not remove features". */}
      <motion.aside
        animate={{ width: collapsed ? 76 : 280 }}
        transition={{ duration: 0.22, ease: "easeInOut" }}
        className="hidden lg:block fixed left-0 top-0 h-screen z-50 overflow-hidden"
      >
        {content}
      </motion.aside>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/40 z-40 lg:hidden"
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ duration: 0.24, ease: "easeOut" }}
              className="fixed left-0 top-0 h-screen w-[82vw] max-w-[280px] z-50 lg:hidden"
            >
              {content}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
