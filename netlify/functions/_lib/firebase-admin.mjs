import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

let adminApp = null;

export function getAdmin() {
  if (adminApp) return adminApp;
  const existing = getApps();
  if (existing.length) {
    adminApp = existing[0];
  } else {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
    if (!raw) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not configured.");
    let creds;
    try { creds = JSON.parse(raw); } catch { throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON."); }
    adminApp = initializeApp({ credential: cert(creds) });
  }
  return { app: adminApp, db: getFirestore(adminApp), auth: getAuth(adminApp) };
}

export const CORS = {
  "Access-Control-Allow-Origin": process.env.APP_ORIGIN || "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

export function json(status, body) {
  return { statusCode: status, headers: { "Content-Type": "application/json", ...CORS }, body: JSON.stringify(body) };
}

export async function verifyUser(event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const m = header.match(/^Bearer\s+(.+)$/);
  if (!m) throw Object.assign(new Error("Missing bearer token"), { status: 401 });
  const { auth } = getAdmin();
  const decoded = await auth.verifyIdToken(m[1]);
  return decoded.uid;
}
