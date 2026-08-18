import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import Webcam from "react-webcam";
import {
  startMonitoring as apiStartMonitoring,
  monitoringHeartbeat,
  stopMonitoring as apiStopMonitoring,
  refreshSession,
  verifyFace,
} from "../services/api";
import { detectFaceLite, extractDescriptor, assessQuality, loadModels } from "../services/faceIdentity";

const MonitoringContext = createContext(null);

// See LoginPage: after LOGIN -> FACE VERIFIED, the confidence from
// that verification is stashed here so the freshly-mounted (post
// navigate) MonitoringProvider can immediately start the continuous
// monitoring session — "MONITORING SESSION STARTED".
const PENDING_CONFIDENCE_KEY = "ibqc_pending_monitoring_face_confidence";

// PART 4 — configurable monitoring interval, not hard-coded around
// one arbitrary value. Frames are sampled/processed at this interval
// rather than on every webcam frame, to avoid burning CPU/GPU and to
// avoid generating an unbounded number of /face/verify + audit
// entries. Override via VITE_MONITORING_INTERVAL_MS at build time.
const MONITORING_INTERVAL_MS = Number(import.meta.env?.VITE_MONITORING_INTERVAL_MS) || 8000;

// A heartbeat request must fail this many times in a row before the
// UI stops trusting the last-known ACTIVE status and shows
// "connection lost" instead (PART 11) — one blip on a flaky network
// shouldn't flip the whole badge.
const CONNECTION_LOST_AFTER_FAILURES = 2;

const CAMERA_CONSTRAINTS = { width: 320, height: 240, facingMode: "user" };

/**
 * Wraps the authenticated app. Owns the monitoring_session_id, the
 * live MonitoringSnapshot, and the actual continuous-monitoring
 * camera loop:
 *
 *   camera permission -> camera stream -> periodic frame sample ->
 *   face detection -> identity comparison (server-side /face/verify
 *   against the caller's own enrolled descriptor) -> liveness/quality
 *   check -> heartbeat (derived telemetry only, never raw video) ->
 *   backend risk/authorization decision -> updated MonitoringSnapshot
 *
 * Every tick captures a FRESH frame and re-runs detection + identity
 * comparison — nothing here reuses the confidence obtained at login
 * beyond the very first heartbeat sent immediately at `startSession`
 * (before the camera loop has had time to run once), which mirrors
 * exactly what a real "face verified at login, then watched
 * continuously from that instant" flow means.
 *
 * `simulateFaceFailure()` remains as an explicit, clearly-labelled
 * demo/test override (see MonitoringBadge's "(demo)" button) that
 * forces the *next* tick's outcome — it never replaces the real
 * camera-driven loop, it just perturbs one tick of it on purpose.
 */
export function MonitoringProvider({ user, deviceId, sessionId, children }) {
  const [monitoringSessionId, setMonitoringSessionId] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState("");
  // Camera lifecycle: 'idle' | 'requesting' | 'ready' | 'unavailable'
  const [cameraState, setCameraState] = useState("idle");
  // PART 11 — network/backend reachability, independent of `status`.
  const [connectionState, setConnectionState] = useState("connected"); // 'connected' | 'lost'

  const webcamRef = useRef(null);
  const pendingFailuresRef = useRef(0);
  const intervalRef = useRef(null);
  const consecutiveHeartbeatFailuresRef = useRef(0);
  const tickInFlightRef = useRef(false);
  const cameraStateRef = useRef("idle");
  const monitoringStartInFlightRef = useRef(false);
  const lastStartedSessionKeyRef = useRef("");

  useEffect(() => {
    cameraStateRef.current = cameraState;
  }, [cameraState]);

  const stopLoop = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = null;
  }, []);

  // ------------------------------------------------------------------
  // One monitoring tick: sample a frame, run identity + liveness
  // checks against it, then heartbeat the derived result.
  // ------------------------------------------------------------------
  const tick = useCallback(async (currentMonitoringSessionId) => {
    if (tickInFlightRef.current) return; // never overlap ticks
    tickInFlightRef.current = true;

    const forcingFailure = pendingFailuresRef.current > 0;
    if (forcingFailure) pendingFailuresRef.current -= 1;

    let facePresent = false;
    let faceMatchConfidence = null;
    let liveness = false;
    let cameraAvailable = cameraStateRef.current === "ready";

    try {
      if (forcingFailure) {
        // Demo override for this one tick only — see docstring above.
        facePresent = false;
        liveness = false;
      } else if (cameraAvailable) {
        const video = webcamRef.current?.video;
        if (video && video.readyState === 4) {
          const detection = await detectFaceLite(video);
          const quality = assessQuality(detection, video);
          facePresent = !!detection;
          liveness = facePresent && quality.ok;

          if (facePresent) {
            // Only pay for the expensive 128-d descriptor + a real
            // server-side identity comparison when a face was
            // actually found this tick — never send a cached
            // descriptor or a cached confidence value.
            const descriptor = await extractDescriptor(video);
            if (descriptor) {
              const result = await verifyFace(descriptor);
              faceMatchConfidence = result.confidence;
            } else {
              // Detected a face box but couldn't extract a usable
              // descriptor this frame (motion blur, partial
              // occlusion) — treat as present-but-unconfirmed rather
              // than fabricating a confidence value.
              faceMatchConfidence = null;
              liveness = false;
            }
          }
        } else {
          cameraAvailable = false;
        }
      }

      const result = await monitoringHeartbeat(currentMonitoringSessionId, {
        facePresent,
        faceMatchConfidence,
        liveness,
        cameraAvailable,
      });
      console.log("[MONITORING] heartbeat response", result);
      setSnapshot(result);
      setError("");
      setConnectionState("connected");
      consecutiveHeartbeatFailuresRef.current = 0;
    } catch (err) {
      // Network hiccup, backend down, or session gone. PART 11: do
      // NOT keep silently showing the last-known ACTIVE status
      // forever — after enough consecutive misses, surface
      // "connection lost" so the UI stops implying a guarantee the
      // backend hasn't actually made recently.
      consecutiveHeartbeatFailuresRef.current += 1;
      if (consecutiveHeartbeatFailuresRef.current >= CONNECTION_LOST_AFTER_FAILURES) {
        setConnectionState("lost");
      }
      console.error("[MONITORING] heartbeat failed", err);
      setError(err.message || "monitoring heartbeat failed");
    } finally {
      tickInFlightRef.current = false;
    }
  }, []);

  const startSession = useCallback(
    async (faceConfidence, intentId) => {
      if (!user || !deviceId || !sessionId) {
        throw new Error("Monitoring requires a valid authenticated session.");
      }

      const sessionKey = `${user.userId}:${deviceId}:${sessionId}`;
      if (monitoringSessionId && lastStartedSessionKeyRef.current === sessionKey) {
        return snapshot;
      }

      pendingFailuresRef.current = 0;
      consecutiveHeartbeatFailuresRef.current = 0;
      setConnectionState("connected");

      console.log("[MONITORING] auth ready", { userId: user.userId, deviceId, sessionId });
      console.log("[MONITORING] face verified", { confidence: faceConfidence });
      console.log("[MONITORING] starting monitoring...", { deviceId, sessionId, faceConfidence, intentId });

      try {
        const sessionStatus = await refreshSession(sessionId, deviceId, 60);
        console.log("[MONITORING] session ready", sessionStatus);
        if (sessionStatus?.revoked) {
          throw new Error("Monitoring start is blocked by existing ownership/session authorization.");
        }

        if (monitoringStartInFlightRef.current) {
          return snapshot;
        }
        monitoringStartInFlightRef.current = true;

        console.log("[MONITORING] sending start request", {
          userId: user.userId,
          deviceId,
          sessionId,
          faceConfidence,
          intentId,
        });

        // The very first snapshot is seeded from the face verification
        // that just happened at login (payload requires a confidence –
        // this endpoint only STARTS watching, it doesn't re-verify).
        // Every subsequent tick re-verifies for real via the camera
        // loop below.
        const result = await apiStartMonitoring(deviceId, sessionId, faceConfidence, intentId);
        console.log("[MONITORING] start response", result);
        setSnapshot(result);
        setMonitoringSessionId(result.monitoring_session_id);
        lastStartedSessionKeyRef.current = sessionKey;
        console.log("[MONITORING] monitoring session", result.monitoring_session_id);
        return result;
      } catch (err) {
        console.error("[MONITORING] start failed", {
          status: err?.status,
          detail: err?.detail,
          userId: user?.userId,
          deviceId,
          sessionId,
          faceConfidence,
          intentId,
        });
        setError(err?.message || err?.detail || "failed to start monitoring");
        throw err;
      } finally {
        monitoringStartInFlightRef.current = false;
      }
    },
    [deviceId, monitoringSessionId, sessionId, snapshot, user]
  );

  const stopSession = useCallback(async () => {
    stopLoop();
    console.log("[MONITORING] stopping monitoring", { monitoringSessionId });
    if (monitoringSessionId) {
      try {
        await apiStopMonitoring(monitoringSessionId);
      } catch {
        /* best-effort */
      }
    }
    setMonitoringSessionId(null);
    setSnapshot(null);
    setCameraState("idle");
    lastStartedSessionKeyRef.current = "";
    console.log("[MONITORING] stopped");
  }, [monitoringSessionId, stopLoop]);

  const simulateFaceFailure = useCallback((count = 1) => {
    pendingFailuresRef.current += count;
  }, []);

  // Re-establish trust: fresh face verification + a fresh authorized
  // session (bumps `version`, which is exactly what invalidates any
  // stale cryptographic session bound to the old one), then starts a
  // brand-new monitoring session in place of the revoked one.
  const reauthenticate = useCallback(
    async (descriptor) => {
      const faceResult = await verifyFace(descriptor);
      if (!faceResult.verified) {
        throw new Error("Face did not match your enrolled identity.");
      }
      await refreshSession(sessionId, deviceId);
      pendingFailuresRef.current = 0;
      consecutiveHeartbeatFailuresRef.current = 0;
      setConnectionState("connected");
      const result = await apiStartMonitoring(deviceId, sessionId, faceResult.confidence);
      setSnapshot(result);
      setMonitoringSessionId(result.monitoring_session_id);
      return result;
    },
    [deviceId, sessionId]
  );

  // ------------------------------------------------------------------
  // Camera lifecycle: request/open the stream only while a monitoring
  // session is actually running, and preload the face-api models so
  // the first real tick isn't stalled behind a model download.
  // ------------------------------------------------------------------
  useEffect(() => {
    if (!monitoringSessionId) {
      setCameraState("idle");
      return;
    }
    setCameraState((prev) => (prev === "ready" ? prev : "requesting"));
    loadModels().catch(() => {
      /* face-api models failed to load -> ticks will still run with
         cameraAvailable=false until the stream/model recovers */
    });
  }, [monitoringSessionId]);

  // Heartbeat loop — runs at the configured interval, independent of
  // whether the camera has finished opening yet (an unopened/denied
  // camera still produces a valid tick: cameraAvailable=false).
  useEffect(() => {
    stopLoop();
    if (!monitoringSessionId) return undefined;
    console.log("[MONITORING] heartbeat started", { monitoringSessionId, intervalMs: MONITORING_INTERVAL_MS });
    intervalRef.current = setInterval(() => tick(monitoringSessionId), MONITORING_INTERVAL_MS);
    return stopLoop;
  }, [monitoringSessionId, tick, stopLoop]);

  // LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED. Runs once
  // per mount (i.e. once per navigation into the authenticated shell)
  // when there's a pending confidence value from a just-completed
  // face verification/enrollment and no session running yet.
  useEffect(() => {
    const pending = sessionStorage.getItem(PENDING_CONFIDENCE_KEY);
    const canStart = Boolean(pending && user && deviceId && sessionId && !monitoringSessionId && !monitoringStartInFlightRef.current);
    if (canStart) {
      console.log("[MONITORING] bootstrap trigger", { userId: user.userId, deviceId, sessionId, pending });
      sessionStorage.removeItem(PENDING_CONFIDENCE_KEY);
      startSession(parseFloat(pending)).catch((err) => setError(err.message || "failed to start monitoring"));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, deviceId, sessionId, monitoringSessionId]);

  // Session ends (logout) -> stop monitoring entirely, including the
  // camera.
  useEffect(() => {
    if (!user) {
      console.log("[MONITORING] logout detected; stopping monitoring");
      stopLoop();
      setMonitoringSessionId(null);
      setSnapshot(null);
      setCameraState("idle");
      lastStartedSessionKeyRef.current = "";
    }
  }, [user, stopLoop]);

  // Browser tab hidden -> the camera loop is still technically
  // running, but a hidden tab can't meaningfully assert "the enrolled
  // user is present" — surface it as a warning-worthy fact via a
  // forced failed tick rather than silently continuing to report
  // ACTIVE off a frame nobody can see change.
  useEffect(() => {
    function onVisibility() {
      if (document.hidden && monitoringSessionId) {
        pendingFailuresRef.current = Math.max(pendingFailuresRef.current, 1);
      }
    }
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [monitoringSessionId]);

  return (
    <MonitoringContext.Provider
      value={{
        monitoringSessionId,
        snapshot,
        error,
        cameraState,
        connectionState,
        isMonitoring: !!monitoringSessionId,
        startSession,
        stopSession,
        simulateFaceFailure,
        reauthenticate,
      }}
    >
      {children}
      {/* Hidden capture surface for the continuous-monitoring loop.
          Rendered off-screen (never display:none, which some browsers
          use to pause decoding) whenever a monitoring session is
          active, and unmounted — which releases the camera device —
          the instant it isn't. No frame from this element is ever
          uploaded; only derived booleans/confidence leave the
          browser. */}
      {monitoringSessionId && (
        <div
          aria-hidden="true"
          style={{ position: "fixed", top: 0, left: 0, width: 1, height: 1, overflow: "hidden", opacity: 0, pointerEvents: "none" }}
        >
          <Webcam
            ref={webcamRef}
            audio={false}
            videoConstraints={CAMERA_CONSTRAINTS}
            onUserMedia={() => setCameraState("ready")}
            onUserMediaError={() => setCameraState("unavailable")}
          />
        </div>
      )}
    </MonitoringContext.Provider>
  );
}

export function useMonitoringContext() {
  const ctx = useContext(MonitoringContext);
  if (!ctx) {
    throw new Error("useMonitoringContext must be used within a MonitoringProvider");
  }
  return ctx;
}
