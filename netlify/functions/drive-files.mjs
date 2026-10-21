import { getAdmin, verifyUser, json, CORS } from "./_lib/firebase-admin.mjs";

async function accessTokenFor(uid) {
  const { db } = getAdmin();
  const ref = db.collection("providerTokens").doc(`${uid}_googleDrive`);
  const snap = await ref.get();
  if (!snap.exists) throw Object.assign(new Error("not_connected"), { status: 400 });
  
  const { refreshToken } = snap.data();
  const body = new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, refresh_token: refreshToken, grant_type: "refresh_token" });
  const res = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const tokens = await res.json();
  
  if (!res.ok) {
    if (tokens.error === "invalid_grant") { await db.collection("storageConnections").doc(`${uid}_googleDrive`).set({ status: "needs_reconnect", updatedAt: new Date() }, { merge: true }); }
    throw Object.assign(new Error("token_refresh_failed"), { status: 401, detail: tokens });
  }
  return tokens.access_token;
}

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS };
  try {
    const uid = await verifyUser(event);
    const token = await accessTokenFor(uid);
    const params = new URLSearchParams({ pageSize: "50", fields: "files(id,name,mimeType,size,modifiedTime,parents,iconLink,webViewLink)", q: "trashed=false", orderBy: "modifiedTime desc" });
    const res = await fetch(`https://www.googleapis.com/drive/v3/files?${params}`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    if (!res.ok) return json(res.status, { error: "drive_error", detail: data });
    return json(200, { files: data.files || [] });
  } catch (err) {
    return json(err.status || 500, { error: err.message, detail: err.detail });
  }
}
