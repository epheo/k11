/**
 * Who runs hosts agents commonly reach, by name suffix, so a notice says at
 * a glance what it is about. A label, not a verdict: an agent sending
 * secrets to GitHub is still news.
 */
const KNOWN: [suffix: string, label: string][] = [
  ["api.anthropic.com", "Anthropic API"],
  ["anthropic.com", "Anthropic"],
  ["claude.ai", "Anthropic"],
  ["api.openai.com", "OpenAI API"],
  ["openai.com", "OpenAI"],
  ["chatgpt.com", "OpenAI"],
  ["generativelanguage.googleapis.com", "Gemini API"],
  ["datadoghq.com", "Datadog telemetry"],
  ["datadoghq.eu", "Datadog telemetry"],
  ["sentry.io", "Sentry error reports"],
  ["statsig.com", "Statsig feature flags"],
  ["api.github.com", "GitHub API"],
  ["githubusercontent.com", "GitHub content"],
  ["github.com", "GitHub"],
  ["ghcr.io", "GitHub container registry"],
  ["gitlab.com", "GitLab"],
  ["registry.npmjs.org", "npm registry"],
  ["yarnpkg.com", "Yarn registry"],
  ["pypi.org", "PyPI"],
  ["pythonhosted.org", "PyPI files"],
  ["crates.io", "crates.io"],
  ["proxy.golang.org", "Go module proxy"],
  ["docker.io", "Docker Hub"],
];

/** The label of the longest suffix that ends `host` on a dot. */
export function knownHost(host: string | undefined): string | undefined {
  if (!host) return undefined;
  let best: [string, string] | undefined;
  for (const k of KNOWN) {
    const [suffix] = k;
    if ((host === suffix || host.endsWith("." + suffix)) && suffix.length > (best?.[0].length ?? 0)) {
      best = k;
    }
  }
  return best?.[1];
}
