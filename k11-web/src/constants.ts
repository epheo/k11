/** Agent CLIs, by the program name their process runs as. */
export const AGENT_PRESETS: { label: string; name: string }[] = [
  { label: "Claude Code", name: "claude" },
  { label: "Codex", name: "codex" },
  { label: "Gemini CLI", name: "gemini" },
  { label: "Copilot CLI", name: "copilot" },
  { label: "Cursor", name: "cursor-agent" },
  { label: "OpenCode", name: "opencode" },
  { label: "Aider", name: "aider" },
  { label: "Goose", name: "goose" },
  { label: "Amp", name: "amp" },
];

/** Raw log events kept in the browser. */
export const MAX_EVENTS = 5000;

/** Raw log rows rendered at once (the newest). */
export const RAW_LOG_RENDER_CAP = 300;

/** Process table rows rendered before "show all". */
export const PROC_TABLE_CAP = 500;

/** Notices kept in the browser; the daemon keeps as many. */
export const MAX_NOTICES = 500;

/** More new notices than this in one poll make one desktop alert. */
export const NOTICE_BURST = 3;

/** Agent list poll; unchanged lists cost the daemon nothing. */
export const POLL_INTERVAL_MS = 1000;

/** Longest wait between activity on the selected agent and its detail refresh. */
export const DETAIL_THROTTLE_MS = 750;

/** Delay before re-subscribing after an unexpected stream end. */
export const RECONNECT_DELAY_MS = 2000;

/** A running agent quiet this long is shown idle: a session left open. */
export const IDLE_AFTER_MS = 5 * 60_000;
