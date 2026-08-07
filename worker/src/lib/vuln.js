/**
 * Known-exposure / advisory fingerprints (scaffold).
 * Safe checks only — no exploit payloads.
 * To be expanded and wired into public /v1/check + CLI.
 */

export const ADVISORIES = [
  {
    id: "CVE-2024-37032",
    stacks: ["ollama"],
    title: "Ollama model-name / path handling class",
    severity: "high",
    remediation:
      "Upgrade Ollama; bind localhost; reverse-proxy auth; reject path-like model names.",
  },
  {
    id: "RAY-OPEN-DASHBOARD",
    stacks: ["ray"],
    title: "Ray dashboard reachable without auth (exposure class)",
    severity: "critical",
    remediation: "Do not expose port 8265; network policy; Anyscale open-ports-checker pattern.",
  },
  {
    id: "JUPYTER-NO-TOKEN",
    stacks: ["jupyter_open"],
    title: "Jupyter without token gate",
    severity: "critical",
    remediation: "Require token; never publish 8888 publicly.",
  },
  {
    id: "OPENAI-COMPAT-UNAUTH",
    stacks: ["vllm", "localai", "litellm", "openai_compat_8000", "openai_compat_8080"],
    title: "OpenAI-compatible API without auth",
    severity: "high",
    remediation: "API keys + network isolation.",
  },
];

/**
 * Given a successful exposure probe result, return matching advisory stubs.
 * Version-aware matching can be added when we parse banners.
 */
export function matchAdvisories({ stack, exposed }) {
  if (!exposed) return [];
  return ADVISORIES.filter((a) => a.stacks.includes(stack)).map((a) => ({
    id: a.id,
    title: a.title,
    severity: a.severity,
    remediation: a.remediation,
  }));
}
