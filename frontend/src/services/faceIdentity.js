/**
 * Face identity extraction — client-side, via @vladmandic/face-api.
 *
 * The reference project's `faceApi.js` loaded `faceExpressionNet` and
 * used the detected *emotion* as a signal fed into key derivation.
 * This module intentionally does something different: it loads
 * `tinyFaceDetector`, `faceLandmark68Net`, and `faceRecognitionNet` to
 * produce a 128-d identity descriptor, matching what
 * `authentication.face_auth.FaceAuthService` on the backend expects.
 * Nothing here classifies expression, and the descriptor this module
 * produces is only ever sent to `/api/face/enroll` or included in a
 * `/api/decrypt` request's `face_descriptor` field — never used to
 * derive a key or populate a CID.
 */
import * as faceapi from "@vladmandic/face-api";

const MODEL_URL = "/models";
let modelsLoaded = false;

export async function loadModels() {
  if (modelsLoaded) return;
  await Promise.all([
    faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
    faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
    faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
  ]);
  modelsLoaded = true;
}

/**
 * Run detection + landmarks + descriptor extraction against a video
 * or canvas element. Returns a plain 128-length number[] (JSON-safe),
 * or null if no face was detected.
 */
export async function extractDescriptor(mediaElement) {
  if (!modelsLoaded) await loadModels();

  const detection = await faceapi
    .detectSingleFace(mediaElement, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks()
    .withFaceDescriptor();

  if (!detection) return null;
  return Array.from(detection.descriptor);
}

export function isReady() {
  return modelsLoaded;
}

/**
 * Lightweight per-frame detection for the live camera overlay
 * (bounding box + landmarks, no 128-d descriptor — that's only
 * computed at actual capture moments, since it's the expensive step).
 */
export async function detectFaceLite(mediaElement) {
  if (!modelsLoaded) await loadModels();
  const detection = await faceapi
    .detectSingleFace(mediaElement, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks();
  return detection || null;
}

/**
 * Heuristic frame-quality assessment used to drive the face-alignment
 * guide and to gate which frames are eligible for capture. Nothing
 * here does identity comparison — that stays server-side.
 */
export function assessQuality(detection, mediaElement) {
  if (!detection) {
    return { ok: false, centered: false, sized: false, sharp: false, lit: false, reasons: ["No face detected"] };
  }
  const { box } = detection.detection;
  const w = mediaElement.videoWidth || mediaElement.width || 1;
  const h = mediaElement.videoHeight || mediaElement.height || 1;

  const boxCenterX = box.x + box.width / 2;
  const boxCenterY = box.y + box.height / 2;
  const offsetX = Math.abs(boxCenterX - w / 2) / w;
  const offsetY = Math.abs(boxCenterY - h / 2) / h;
  const centered = offsetX < 0.18 && offsetY < 0.18;

  const relativeSize = box.width / w;
  const sized = relativeSize > 0.22 && relativeSize < 0.85;

  // face-api's detector score is a reasonable proxy for sharpness /
  // occlusion — a blurry or partially-hidden face scores lower.
  const sharp = detection.detection.score > 0.75;

  const landmarksOk = detection.landmarks?.positions?.length === 68;

  const reasons = [];
  if (!centered) reasons.push("Center your face in the guide");
  if (!sized) reasons.push(relativeSize <= 0.22 ? "Move closer" : "Move back a little");
  if (!sharp) reasons.push("Hold still / improve lighting");
  if (!landmarksOk) reasons.push("Face not fully visible");

  return {
    ok: centered && sized && sharp && landmarksOk,
    centered,
    sized,
    sharp,
    lit: sharp,
    reasons,
  };
}
