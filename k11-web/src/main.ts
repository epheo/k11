import { mount } from "svelte";

import App from "./App.svelte";
import "./style.css";
import { loadConfig, loadPolicy, refreshAgents } from "./api.ts";
import { startStream } from "./stream.ts";

const app = mount(App, { target: document.getElementById("app")! });

(async () => {
  await Promise.all([loadConfig(), loadPolicy(), refreshAgents()]);
  startStream();
})();

export default app;
