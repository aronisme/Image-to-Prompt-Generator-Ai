// netlify/functions/verify.js
const crypto = require("crypto");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }
  const body = JSON.parse(event.body || "{}");
  const code = (body.code || "").toString();

  const SECRET_CODE = process.env.SECRET_CODE || "";
  const SIGN_KEY = process.env.SIGN_KEY || "";

  if (!SECRET_CODE || !SIGN_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ ok: false, message: "Server not configured" }),
    };
  }

  if (code !== SECRET_CODE) {
    return { statusCode: 401, body: JSON.stringify({ ok: false, message: "Kode salah" }) };
  }

  // Buat payload token (simple): {iat, exp}
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 15 * 60; // 15 menit
  const payload = JSON.stringify({ iat, exp });

  // signature = HMAC-SHA256(payload, SIGN_KEY)
  const hmac = crypto.createHmac("sha256", SIGN_KEY).update(payload).digest("base64url");

  const token = `${Buffer.from(payload).toString("base64url")}.${hmac}`;

  return {
    statusCode: 200,
    body: JSON.stringify({ ok: true, token }),
  };
};
