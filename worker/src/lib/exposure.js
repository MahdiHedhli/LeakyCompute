/**
 * Exposure classes — what an open endpoint *enables*, grouped.
 *
 * Derived from the stack, not from a stored field, so it covers 100% of the
 * corpus rather than the 13% that happens to disclose a version string. It is
 * a pure function of stats:by_stack, so it costs no writes and works on records
 * that predate it.
 *
 * The claim each class makes is deliberately about reachability, never about
 * exploitability (I-3). "This endpoint answers unauthenticated requests, and
 * that class of access enables X" is something we observed. "Exploitable" is
 * not, because we never tried — and the difference is the whole project.
 */

export const EXPOSURE_CLASSES = [
  {
    id: "code_execution",
    label: "Code execution reachable",
    severity: "critical",
    // Services whose documented purpose is running user-supplied code. An open
    // one is not "vulnerable" — it is working as designed, at the internet.
    stacks: ["jupyter", "jupyter_open", "ray"],
    detail:
      "Notebook servers answering without a token, and Ray Jobs APIs answering " +
      "without auth. Submitting work to either is running code on that machine. " +
      "These are the preconditions for CVE-2023-48022; Ray ships no auth by " +
      "design, so no upgrade closes it.",
  },
  {
    id: "compute_abuse",
    label: "Workflow execution open",
    severity: "high",
    stacks: ["comfyui"],
    detail:
      "Generation pipelines that accept and run workflows from anyone who can " +
      "reach them. The GPU time is the operator's.",
  },
  {
    id: "model_access",
    label: "Models and inference open",
    severity: "high",
    stacks: [
      "ollama",
      "open_webui",
      "vllm",
      "localai",
      "litellm",
      "triton",
      "openai_compat_8000",
      "openai_compat_8080",
      "gradio",
    ],
    detail:
      "Model lists readable and inference callable without credentials — the " +
      "operator's hardware, and on proxied stacks their upstream API bill.",
  },
  {
    id: "ml_metadata",
    label: "Training data and artifacts open",
    severity: "medium",
    stacks: ["mlflow", "tensorboard"],
    detail:
      "Experiment tracking and training dashboards readable by anyone. These " +
      "leak datasets, metrics, model lineage and sometimes credentials in run " +
      "parameters.",
  },
];

const STACK_TO_CLASS = new Map();
for (const c of EXPOSURE_CLASSES) {
  for (const s of c.stacks) STACK_TO_CLASS.set(s, c.id);
}

/**
 * Count hosts per exposure class from the by_stack aggregate.
 *
 * A stack we have not classified is surfaced under `unclassified` rather than
 * dropped: a new lane must not quietly shrink the totals on this row.
 */
export function exposureClassCounts(byStack) {
  const rows = Array.isArray(byStack) ? byStack : [];
  const counts = new Map(EXPOSURE_CLASSES.map((c) => [c.id, 0]));
  const stacksByClass = new Map(EXPOSURE_CLASSES.map((c) => [c.id, []]));
  let unclassified = 0;
  const unclassifiedStacks = [];

  for (const r of rows) {
    const stack = r?.stack;
    const n = Number(r?.count) || 0;
    if (!stack || n <= 0) continue;
    const cls = STACK_TO_CLASS.get(stack);
    if (!cls) {
      unclassified += n;
      unclassifiedStacks.push(stack);
      continue;
    }
    counts.set(cls, counts.get(cls) + n);
    stacksByClass.get(cls).push(`${stack} ${n}`);
  }

  const classes = EXPOSURE_CLASSES.filter((c) => counts.get(c.id) > 0).map((c) => ({
    id: c.id,
    label: c.label,
    severity: c.severity,
    hosts: counts.get(c.id),
    stacks: stacksByClass.get(c.id).join(" · "),
    detail: c.detail,
  }));
  classes.sort((a, b) => b.hosts - a.hosts);

  return {
    classes,
    unclassified,
    unclassified_stacks: unclassifiedStacks,
    // Host+stack pairs, so this exceeds the distinct-host count when one host
    // exposes more than one service. Said here so the UI cannot imply otherwise.
    total_pairs: rows.reduce((a, r) => a + (Number(r?.count) || 0), 0),
    note:
      "Counted from host+stack pairs, so a host exposing two services appears " +
      "in two classes. Describes what each open endpoint enables — reachability " +
      "we observed, never exploitability we tested (I-3).",
  };
}
