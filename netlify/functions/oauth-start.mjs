import crypto from "node:crypto";
import { getAdmin, CORS, verifyUser, json } from "./_lib/firebase-admin.mjs";

const SCOPES = ["https://www.googleapis.com/auth/drive.file"];

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const uid = await verifyUser(event);
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = process.env.OAUTH_REDIRECT_URI;
    
    if (!clientId || !redirectUri) return json(500, { error: "oauth_not_configured", detail: "Environment variables missing." });
    
    const state = crypto.randomBytes(24).toString("hex");
    const codeVerifier = crypto.randomBytes(64).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const { db } = getAdmin();
    
    await db.collection("oauthStates").doc(state).set({ uid, codeVerifier, createdAt: new Date(Date.now()), expiresAt: new Date(Date.now() + 10 * 60 * 1000) });
    
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", SCOPES.join(" "));
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    
    return { statusCode: 302, headers: { Location: url.toString(), ...CORS }, body: "" };
  } catch (err) {
    return json(err.status || 400, { error: "oauth_start_failed", message: err.message });
  }
}
