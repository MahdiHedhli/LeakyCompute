/**
 * The test fixtures bind fake services to the same ports the tier-1 checker
 * probes. The local fingerprint lab (scripts/discovery/local-lab) binds those
 * same ports, so the two cannot run at once. Fail with something readable
 * instead of a raw EADDRINUSE stack.
 */
import net from "node:net";

export async function requirePorts(ports) {
  const busy = [];
  for (const p of ports) {
    const free = await new Promise((resolve) => {
      const s = net.createServer();
      s.once("error", () => resolve(false));
      s.once("listening", () => s.close(() => resolve(true)));
      s.listen(p, "127.0.0.1");
    });
    if (!free) busy.push(p);
  }
  if (busy.length) {
    console.error(
      `\n[preflight] port(s) in use: ${busy.join(", ")}\n` +
        `These are the ports the test fixtures need.\n` +
        `The fingerprint lab is probably running — stop it and re-run:\n\n` +
        `  docker compose -f scripts/discovery/local-lab/docker-compose.yml down\n`
    );
    process.exit(1);
  }
}
