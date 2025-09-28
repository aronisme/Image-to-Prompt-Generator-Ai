// netlify/functions/validate.js
const crypto = require("crypto");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }
  const body = JSON.parse(event.body || "{}");
  const token = (body.token || "").toString();

  const SIGN_KEY = process.env.SIGN_KEY || "";
  if (!SIGN_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ ok: false, message: "Server not configured" }),
    };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { statusCode: 400, body: JSON.stringify({ ok: false, message: "Token invalid" }) };
  }

  const [b64payload, sig] = parts;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(b64payload, "base64url").toString("utf-8"));
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ ok: false, message: "Token parse error" }) };
  }

  const expectedHmac = crypto.createHmac("sha256", SIGN_KEY).update(JSON.stringify(payload)).digest("base64url");

  // compare secara aman
  const validSig = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedHmac));

  if (!validSig) {
    return { statusCode: 401, body: JSON.stringify({ ok: false, message: "Signature mismatch" }) };
  }

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || now > payload.exp) {
    return { statusCode: 401, body: JSON.stringify({ ok: false, message: "Token expired" }) };
  }

  return { statusCode: 200, body: JSON.stringify({ ok: true }) };
};
