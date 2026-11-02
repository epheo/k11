/** Raw log events kept in the browser. */
export const MAX_EVENTS = 5000;

/** Raw log rows rendered at once (the newest). */
export const RAW_LOG_RENDER_CAP = 300;

/** Process table rows rendered before "show all". */
export const PROC_TABLE_CAP = 500;

/** Agent list poll; unchanged lists cost the daemon nothing. */
export const POLL_INTERVAL_MS = 1000;

/** Longest wait between activity on the selected agent and its detail refresh. */
export const DETAIL_THROTTLE_MS = 750;

/** Delay before re-subscribing after an unexpected stream end. */
export const RECONNECT_DELAY_MS = 2000;
