import { getAdmin, json, CORS } from "./_lib/firebase-admin.mjs";

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== "GET") return json(405, { error: "method_not_allowed" });

  const code = event.queryStringParameters?.code;
  const state = event.queryStringParameters?.state;
  const errParam = event.queryStringParameters?.error;
  const appOrigin = process.env.APP_ORIGIN || "/";
  
  if (errParam) return { statusCode: 302, headers: { Location: `${appOrigin}/#connections?error=${encodeURIComponent(errParam)}` } };
  if (!code || !state) return json(400, { error: "missing_code_or_state" });

  try {
    const { db } = getAdmin();
    const stateDoc = await db.collection("oauthStates").doc(state).get();
    if (!stateDoc.exists) return json(400, { error: "invalid_state" });
    
    const st = stateDoc.data();
    if (new Date(st.expiresAt.toDate ? st.expiresAt.toDate() : st.expiresAt) < new Date()) {
      await stateDoc.ref.delete(); return json(400, { error: "state_expired" });
    }
    
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.OAUTH_REDIRECT_URI;
    
    if (!clientId || !clientSecret || !redirectUri) return json(500, { error: "oauth_not_configured" });
    
    const body = new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: "authorization_code", code_verifier: st.codeVerifier });
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    const tokens = await tokenRes.json();
    
    if (!tokenRes.ok) { await stateDoc.ref.delete(); return json(400, { error: "token_exchange_failed", detail: tokens }); }
    
    let accountEmail = "";
    try {
      const meRes = await fetch("https://www.googleapis.com/drive/v3/about?fields=user", { headers: { Authorization: `Bearer ${tokens.access_token}` } });
      if (meRes.ok) { const me = await meRes.json(); accountEmail = me.user?.emailAddress || ""; }
    } catch { }
    
    const uid = st.uid;
    if (tokens.refresh_token) {
      await db.collection("providerTokens").doc(`${uid}_googleDrive`).set({ uid, provider: "googleDrive", refreshToken: tokens.refresh_token, scope: tokens.scope || "", updatedAt: new Date() }, { merge: true });
    }
    
    await db.collection("storageConnections").doc(`${uid}_googleDrive`).set({ ownerUid: uid, provider: "googleDrive", accountEmail, status: "connected", scopes: tokens.scope || "", connectedAt: new Date(), updatedAt: new Date() }, { merge: true });
    
    await stateDoc.ref.delete();
    return { statusCode: 302, headers: { Location: `${appOrigin}/#connections?connected=googleDrive` } };
  } catch (err) {
    console.error("oauth-callback error:", err);
    return json(500, { error: "callback_failed", message: err.message });
  }
}
