import crypto from "node:crypto";
import { getAdmin, verifyUser, json, CORS } from "./_lib/firebase-admin.mjs";

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS };
  try {
    const uid = await verifyUser(event);
    const body = event.body ? JSON.parse(event.body) : {};
    const action = body.action;
    const { db } = getAdmin();

    if (action === "create") {
      const { fileId, expiresInDays = 7 } = body;
      if (!fileId || typeof fileId !== "string") return json(400, { error: "fileId_required" });
      const fileDoc = await db.collection("files").doc(fileId).get();
      if (!fileDoc.exists) return json(404, { error: "file_not_found" });
      if (fileDoc.data().ownerUid !== uid) return json(403, { error: "not_owner" });
      
      const token = crypto.randomBytes(32).toString("base64url");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      const expiresAt = new Date(Date.now() + Math.max(1, Math.min(365, expiresInDays)) * 86400000);
      
      await db.collection("publicLinks").doc(tokenHash).set({ ownerUid: uid, fileId, tokenHash, createdAt: new Date(), expiresAt, revoked: false });
      return json(200, { shareUrl: `${process.env.APP_ORIGIN}/s/${token}`, expiresAt });
    }

    if (action === "revoke") {
      const { linkId } = body;
      if (!linkId) return json(400, { error: "linkId_required" });
      const ref = db.collection("publicLinks").doc(linkId);
      const snap = await ref.get();
      if (!snap.exists) return json(404, { error: "not_found" });
      if (snap.data().ownerUid !== uid) return json(403, { error: "not_owner" });
      await ref.set({ revoked: true, revokedAt: new Date() }, { merge: true });
      return json(200, { ok: true });
    }

    return json(400, { error: "unknown_action" });
  } catch (err) { return json(err.status || 500, { error: err.message }); }
}
