/** Hash strings for private abuse logs (never store raw IPs in public artifacts). */
export async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashIp(ip, salt) {
  return sha256Hex(`${salt || "leakycompute"}|${ip || "unknown"}`);
}
