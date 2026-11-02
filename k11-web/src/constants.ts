/** Max events kept in the in-memory ring buffer for the raw log. */
export const MAX_EVENTS = 5000;

/** Cap of rows actually rendered in the raw log at once (tail window). */
export const RAW_LOG_RENDER_CAP = 300;

/** Cap of rows rendered in the process table before "show all" prompt. */
export const PROC_TABLE_CAP = 500;

/** Debounce between a stream event arriving and triggering refreshAgents + loadDetail. */
export const REFRESH_INTERVAL_MS = 750;

/** Delay before re-subscribing after an unexpected stream disconnect. */
export const RECONNECT_DELAY_MS = 2000;

/** GetAgentEvents page size when (re)loading events for a selected agent. */
export const EVENTS_PAGE_SIZE = MAX_EVENTS;
