import crypto from "node:crypto";
import { getAdmin, json, CORS } from "./_lib/firebase-admin.mjs";

const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const window = 60_000, max = 60;
  const arr = (hits.get(ip) || []).filter((t) => now - t < window);
  arr.push(now); hits.set(ip, arr);
  return arr.length > max;
}

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS };
  const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "unknown";
  if (rateLimited(ip)) return json(429, { error: "rate_limited" });

  const token = event.queryStringParameters?.token;
  if (!token) return json(400, { error: "missing_token" });
  
  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const { db } = getAdmin();
    const linkSnap = await db.collection("publicLinks").doc(tokenHash).get();
    if (!linkSnap.exists) return json(404, { error: "not_found" });
    
    const link = linkSnap.data();
    if (link.revoked) return json(410, { error: "revoked" });
    
    const exp = link.expiresAt?.toDate ? link.expiresAt.toDate() : new Date(link.expiresAt);
    if (exp < new Date()) return json(410, { error: "expired" });

    const fileDoc = await db.collection("files").doc(link.fileId).get();
    if (!fileDoc.exists) return json(404, { error: "file_missing" });
    
    const file = fileDoc.data();
    return json(200, { file: { name: file.name, mimeType: file.mimeType, size: file.size, updatedAt: file.updatedAt } });
  } catch (err) { return json(500, { error: "share_lookup_failed" }); }
}
