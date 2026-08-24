(async () => {
  const fallbackBootstrap = {
    proxy_port: 8080,
    display_config: {
      labels: {},
      keys: {},
      raw_request_fields: [],
    },
  };

  async function fetchBootstrap() {
    try {
      const response = await fetch("/api/bootstrap");
      if (!response.ok) {
        return fallbackBootstrap;
      }
      return { ...fallbackBootstrap, ...(await response.json()) };
    } catch {
      return fallbackBootstrap;
    }
  }

  const bootstrap = await fetchBootstrap();
  const requests = new Map();
  let selectedId = null;
  let jsonMode = localStorage.getItem("wiretap-json-mode") === "1";
  let settingsCollapsed = localStorage.getItem("wiretap-settings-collapsed") === "1";

  const listEl = document.getElementById("list");
  const detailsEl = document.getElementById("details");
  const metaEl = document.getElementById("meta");
  const requestsTotalEl = document.getElementById("requests-total");
  const connectionStateEl = document.getElementById("connection-state");
  const jsonModeBtn = document.getElementById("json-mode");
  const collapseSettingsBtn = document.getElementById("collapse-settings");
  const allowedHostsEl = document.getElementById("allowed-hosts");
  const trackedPathsEl = document.getElementById("tracked-paths");
  const catchAllModeEl = document.getElementById("catch-all-mode");
  const saveStatusEl = document.getElementById("save-status");
  const diagnosticListEl = document.getElementById("diagnostic-list");
  const diagnosticsHintEl = document.getElementById("diagnostics-hint");
  const diagnosticTabsEl = document.getElementById("diagnostic-tabs");
  const liveDiagnosticsEl = document.getElementById("live-diagnostics");
  const runtimeUiEl = document.getElementById("runtime-ui");
  const runtimeProxyEl = document.getElementById("runtime-proxy");
  const configPathEl = document.getElementById("config-path");
  const caPathEl = document.getElementById("ca-path");
  const settingsPanelEl = document.getElementById("settings-panel");
  const ws = new WebSocket((location.protocol === "https:" ? "wss" : "ws") + "://" + location.host + "/ws");
  const DISPLAY = bootstrap.display_config || {};
  const LABELS = DISPLAY.labels || {};
  const KEYS = DISPLAY.keys || {};
  const RAW_FIELDS = DISPLAY.raw_request_fields || [];
  const DIAGNOSTIC_CONFIG = {
    hosts: {
      empty: "No rejected domains yet.",
      key: "host",
      hint: "Hosts that hit tracked endpoints but were not in the allowlist.",
    },
    paths: {
      empty: "No rejected paths yet.",
      key: "path",
      hint: "Observed POST /v1/* paths that were blocked by host rules or are not currently tracked.",
    },
    targets: {
      empty: "No POST targets seen yet.",
      key: "target",
      hint: "Every POST target observed by the proxy.",
    },
  };

  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  const label = (name, fallback) => LABELS[name] || fallback;
  const keyLabel = (name) => KEYS[name] || name;
  const getReqBody = (req) => req?.request_body ?? null;
  const getRespBody = (req) => req?.response_body ?? null;
  const getDuration = (req) => req?.duration_ms;
  const getRawResponse = (req) => req?.raw_response_text ?? "";
  const getSseEvents = (req) => req?.sse_events ?? [];
  const isStreaming = (req) => Boolean(req?.is_streaming);
  let activeDiagnosticTab = "hosts";
  let socketState = "Connecting";
  let jsonBlockSeq = 0;
  const rawJsonStore = new Map();
  let settingsData = {
    rejected_hosts: [],
    rejected_paths: [],
    seen_post_targets: [],
  };

  const setStatus = (text, kind) => {
    saveStatusEl.textContent = text;
    saveStatusEl.className = "status" + (kind ? " " + kind : "");
  };

  const renderRows = (container, items, emptyText, valueKey) => {
    if (!items.length) {
      container.innerHTML = `<div class="empty">${esc(emptyText)}</div>`;
      return;
    }
    container.innerHTML = items.map((item) => `<div class="row"><span>${esc(item[valueKey])}</span><span class="count">${esc(item.count)}x</span></div>`).join("");
  };

  const renderDiagnostics = () => {
    const tabConfig = DIAGNOSTIC_CONFIG[activeDiagnosticTab];
    const datasetByTab = {
      hosts: settingsData.rejected_hosts || [],
      paths: settingsData.rejected_paths || [],
      targets: settingsData.seen_post_targets || [],
    };
    diagnosticsHintEl.textContent = tabConfig.hint;
    renderRows(diagnosticListEl, datasetByTab[activeDiagnosticTab], tabConfig.empty, tabConfig.key);
    diagnosticTabsEl.querySelectorAll(".diag-tab").forEach((button) => {
      button.classList.toggle("active", button.dataset.tab === activeDiagnosticTab);
    });
    document.getElementById("count-hosts").textContent = String(datasetByTab.hosts.length);
    document.getElementById("count-paths").textContent = String(datasetByTab.paths.length);
    document.getElementById("count-targets").textContent = String(datasetByTab.targets.length);
  };

  const syncSettingsCollapseButton = () => {
    const isCollapsed = settingsCollapsed;
    collapseSettingsBtn.textContent = isCollapsed ? ">" : "<";
    collapseSettingsBtn.title = isCollapsed ? "Expand settings" : "Collapse settings";
    collapseSettingsBtn.setAttribute("aria-label", isCollapsed ? "Expand settings" : "Collapse settings");
    collapseSettingsBtn.setAttribute("aria-expanded", isCollapsed ? "false" : "true");
  };

  const syncSettingsPanel = () => {
    document.body.classList.toggle("settings-collapsed", settingsCollapsed);
    syncSettingsCollapseButton();
  };

  const toggleSettingsCollapse = () => {
    settingsCollapsed = !settingsCollapsed;
    localStorage.setItem("wiretap-settings-collapsed", settingsCollapsed ? "1" : "0");
    syncSettingsPanel();
    settingsPanelEl.scrollTo({ top: 0, behavior: "smooth" });
  };

  const loadSettings = async () => {
    setStatus("Loading...", "warn");
    const response = await fetch("/api/settings");
    if (!response.ok) {
      throw new Error("Failed to load settings");
    }
    const data = await response.json();
    settingsData = data;
    allowedHostsEl.value = (data.allowed_hosts || []).join("\n");
    trackedPathsEl.value = (data.tracked_paths || []).join("\n");
    catchAllModeEl.checked = Boolean(data.catch_all_mode);
    runtimeUiEl.textContent = `:${data.ui_port ?? ""}`;
    runtimeProxyEl.textContent = `:${data.proxy_port ?? ""}`;
    configPathEl.textContent = "Allowed hosts JSON: " + (data.allowed_hosts_config_path || "");
    caPathEl.textContent = "CA: " + (data.ca_path || "");
    renderDiagnostics();
    setStatus("Loaded", "ok");
  };

  const saveSettings = async () => {
    const allowedHosts = allowedHostsEl.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    const trackedPaths = trackedPathsEl.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    setStatus("Saving...", "warn");
    const response = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        allowed_hosts: allowedHosts,
        tracked_paths: trackedPaths,
        clear_rejected_hosts: false,
        catch_all_mode: catchAllModeEl.checked,
      }),
    });
    if (!response.ok) {
      throw new Error("Failed to save settings");
    }
    await loadSettings();
    setStatus("Saved", "ok");
  };

  const clearRejected = async () => {
    const response = await fetch("/api/rejected/clear", { method: "POST" });
    if (!response.ok) {
      throw new Error("Failed to clear debug state");
    }
    await loadSettings();
  };

  const clearRequests = async () => {
    const response = await fetch("/clear", { method: "POST" });
    if (!response.ok) {
      throw new Error("Failed to clear requests");
    }
    requests.clear();
    selectedId = null;
    renderList();
    renderDetails();
  };

  const mergeRequest = (incoming) => {
    if (!incoming?.id) {
      return null;
    }
    const current = requests.get(incoming.id) || {};
    const next = { ...current, ...incoming };
    requests.set(next.id, next);
    return next;
  };

  const blocks = (message) => {
    if (!message) {
      return [];
    }
    if (typeof message.content === "string") {
      return [{ type: "text", text: message.content }];
    }
    return Array.isArray(message.content) ? message.content : [];
  };

  const previewText = (list) => {
    for (const block of list || []) {
      if (block.type === "text" && block.text) return block.text.replace(/\s+/g, " ").trim();
      if (block.type === "tool_use") return `Tool: ${block.name || "unknown"}`;
      if (block.type === "tool_result" && typeof block.content === "string") return block.content.replace(/\s+/g, " ").trim();
      if (block.type === "thinking" && block.thinking) return block.thinking.replace(/\s+/g, " ").trim();
    }
    return "";
  };

  const asText = (value) => {
    if (value == null) return "";
    if (typeof value === "string") return value;
    if (Array.isArray(value)) {
      return value
        .map((entry) => (typeof entry === "string" ? entry : ("text" in (entry || {}) ? entry.text : JSON.stringify(entry, null, 2))))
        .join("\n");
    }
    return JSON.stringify(value, null, 2);
  };

  const compactText = (value) => String(value ?? "").replace(/\s+/g, " ").trim();
  const renderPill = (value) => `<span class="pill">${esc(String(value ?? ""))}</span>`;
  const renderPre = (value) => `<pre>${esc(typeof value === "string" ? value : JSON.stringify(value, null, 2))}</pre>`;
  const renderFormattedJson = (container, value) => {
    const Formatter = window.JSONFormatter || window.JSONFormatter?.default;
    if (typeof Formatter !== "function") {
      container.innerHTML = renderPre(value);
      return;
    }
    try {
      const formatter = new Formatter(value, 1, {
        theme: "dark",
        hoverPreviewEnabled: true,
      });
      container.replaceChildren(formatter.render());
    } catch {
      container.innerHTML = renderPre(value);
    }
  };
  const hydrateJsonViews = () => {
    detailsEl.querySelectorAll(".json-raw-view[data-json-id]").forEach((node) => {
      const jsonId = node.dataset.jsonId;
      if (!jsonId || node.dataset.hydrated === "1") {
        return;
      }
      renderFormattedJson(node, rawJsonStore.get(jsonId));
      node.dataset.hydrated = "1";
    });
  };
  const renderKv = (key, content) => `<div class="kv"><div class="kv-key">${esc(keyLabel(key))}</div><div class="kv-val">${content}</div></div>`;
  const renderSummaryMain = (title, preview = "") => `<span class="summary-main"><span>${esc(title)}</span>${preview ? `<span class="summary-preview">${esc(preview)}</span>` : ""}</span>`;
  const attachInlineCopyHandlers = (root) => {
    root?.querySelectorAll(".copy-inline-btn").forEach((button) => {
      if (button.dataset.copyBound === "1") {
        return;
      }
      button.dataset.copyBound = "1";
      button.addEventListener("click", async () => {
        const codeEl = button.parentElement?.querySelector("code");
        if (!codeEl) {
          return;
        }
        try {
          await navigator.clipboard.writeText(codeEl.textContent || "");
          button.textContent = "Copied";
        } catch {
          button.textContent = "Failed";
        }
        setTimeout(() => {
          button.textContent = "Copy";
        }, 1200);
      });
    });
  };
  const renderRawJsonView = (value) => {
    const viewId = `json-block-${++jsonBlockSeq}`;
    rawJsonStore.set(viewId, value);
    return {
      button: `<span class="summary-actions"><button class="summary-json-btn" type="button" data-json-target="${viewId}" aria-pressed="false">JSON</button></span>`,
      panel: `<div class="json-raw-view hidden" id="${viewId}" data-json-id="${viewId}"></div>`,
    };
  };
  const renderDetailsBox = (klass, title, body, options = {}) => {
    const { preview = "", tag = "", open = false, rawValue } = options;
    const rawJson = rawValue === undefined ? null : renderRawJsonView(rawValue);
    return `<details class="${klass}${rawJson ? " json-enabled" : ""}"${open ? " open" : ""}><summary>${renderSummaryMain(title, preview)}${tag}${rawJson ? rawJson.button : ""}</summary><div class="body">${rawJson ? `<div class="json-content-view">${body}</div>${rawJson.panel}` : body}</div></details>`;
  };
  const renderToolSchema = (title, value) => `<details class="tool-schema"><summary>${esc(title)}</summary><div class="tool-schema-body">${renderPre(value)}</div></details>`;

  const renderSystem = (system) => {
    if (!system) return "";
    if (typeof system === "string") {
      return renderDetailsBox("box panel", label("system_prompt", "System Prompt"), renderPre(system), {
        preview: compactText(system),
        rawValue: system,
      });
    }
    if (Array.isArray(system)) {
      const sections = system.map((block) => {
        let html = `<div class="sys-block">${renderKv("type", renderPill(block?.type || "text"))}`;
        if (block?.cache_control) {
          html += renderKv("cache_control", renderPill(block.cache_control.type || "ephemeral"));
        }
        html += `${renderKv("text", renderPre(block?.text || ""))}</div>`;
        return html;
      }).join("");
      return renderDetailsBox("box panel", label("system_prompt", "System Prompt"), sections, {
        preview: compactText(system.map((block) => block?.text || "").join(" ")),
        tag: `<span class="summary-tag">[${system.length} ${esc(label("system_blocks_count", "blocks"))}]</span>`,
        rawValue: system,
      });
    }
    return renderDetailsBox("box panel", label("system_prompt", "System Prompt"), renderPre(system), { rawValue: system });
  };

  const renderRawRequest = (body) => {
    if (!body) return "";
    const renderField = (field) => {
      const value = body[field.key];
      if (value === undefined) return "";
      if (field.kind === "json") {
        if (Array.isArray(value) && value.length === 0) return "";
        return renderKv(field.key, renderPre(value));
      }
      if (field.kind === "bool") {
        return renderKv(field.key, renderPill(Boolean(value)));
      }
      if (field.kind === "count") {
        const count = Array.isArray(value) ? value.length : 0;
        return renderKv(field.key, renderPill(count));
      }
      return renderKv(field.key, renderPill(value));
    };

    const parts = RAW_FIELDS.map(renderField).filter(Boolean);
    parts.push(renderToolSchema(label("full_json", "Full JSON"), body));
    const preview = `${body.model || "unknown"} | ${Array.isArray(body.messages) ? body.messages.length : 0} msgs`;
    return renderDetailsBox("box panel", label("raw_request", "Raw Request"), parts.join(""), { preview, rawValue: body });
  };

  const renderJsonMode = (item) => {
    const body = getReqBody(item);
    const response = getRespBody(item);
    const sections = [];
    sections.push(renderDetailsBox("box panel", "Captured Record", renderPre(item), { open: true, rawValue: item }));
    if (body !== null && body !== undefined) {
      sections.push(renderDetailsBox("box panel", "Request JSON", renderPre(body), { rawValue: body }));
    }
    if (response !== null && response !== undefined) {
      sections.push(renderDetailsBox("box panel", "Response JSON", renderPre(response), { rawValue: response }));
    }
    if (getRawResponse(item)) {
      sections.push(renderDetailsBox("box panel", "Raw Response Text", renderPre(getRawResponse(item)), { rawValue: getRawResponse(item) }));
    }
    if (getSseEvents(item).length) {
      sections.push(renderDetailsBox("box panel", label("streaming_events", "Streaming Events"), renderPre(getSseEvents(item)), {
        preview: `${getSseEvents(item).length} ${label("events", "events")}`,
        rawValue: getSseEvents(item),
      }));
    }
    return sections.join("");
  };

  const imageSrc = (block) => {
    const source = block?.source;
    if (!source || source.type !== "base64" || !source.media_type || !source.data) {
      return "";
    }
    return `data:${source.media_type};base64,${source.data}`;
  };

  const renderContentBlock = (block) => {
    if (!block) return "";
    if (block.type === "text") {
      return `<div class="content-block text-block">${esc(block.text || "")}</div>`;
    }
    if (block.type === "thinking") {
      const body = `${renderKv("thinking", renderPre(block.thinking || ""))}${block.signature ? renderKv("signature", renderPre(block.signature)) : ""}`;
      const rawJson = renderRawJsonView(block);
      return `<details class="subbox content-block json-enabled"><summary><span class="thinking-title">${esc(label("thinking", "THINKING"))}</span>${rawJson.button}</summary><div class="subbody"><div class="json-content-view">${body}</div>${rawJson.panel}</div></details>`;
    }
    if (block.type === "tool_use") {
      const toolName = block.name || "unknown";
      const toolId = block.id ? `<span class="inline-tag">#${esc(block.id)}</span>` : "";
      const body = `${renderKv("name", renderPill(toolName))}${block.id ? renderKv("id", renderPill(block.id)) : ""}${renderKv("input", renderPre(block.input || {}))}`;
      const rawJson = renderRawJsonView(block);
      return `<details class="subbox content-block json-enabled"><summary><span class="tool-call-title">${esc(label("tool_call", "TOOL CALL"))}</span><span class="inline-tag">${esc(toolName)}</span>${toolId}${rawJson.button}</summary><div class="subbody"><div class="json-content-view">${body}</div>${rawJson.panel}</div></details>`;
    }
    if (block.type === "tool_result") {
      const klass = block.is_error ? "tool-result-title error" : "tool-result-title";
      const tag = block.is_error ? `<span class="inline-tag">[error]</span>` : "";
      const body = `${block.tool_use_id ? renderKv("tool_use_id", renderPill(block.tool_use_id)) : ""}${renderKv("content", renderPre(asText(block.content)))}${block.is_error ? renderKv("is_error", renderPill(true)) : ""}`;
      const rawJson = renderRawJsonView(block);
      return `<details class="subbox content-block json-enabled"><summary><span class="${klass}">${esc(label("tool_result", "TOOL RESULT"))}</span>${tag}${rawJson.button}</summary><div class="subbody"><div class="json-content-view">${body}</div>${rawJson.panel}</div></details>`;
    }
    if (block.type === "image") {
      const source = imageSrc(block);
      const rawJson = renderRawJsonView(block);
      return `<details class="subbox content-block json-enabled"><summary><span class="inline-tag">${esc(label("image", "IMAGE"))}</span>${rawJson.button}</summary><div class="subbody"><div class="json-content-view">${source ? `<div class="img-wrap"><img alt="Captured image block" src="${source}"></div>` : ""}${renderKv("source", renderPre(block.source || {}))}</div>${rawJson.panel}</div></details>`;
    }
    return `<div class="content-block">${renderPre(block)}</div>`;
  };

  const renderMsg = (role, list, stop = "", rawValue = null) => {
    const preview = previewText(list);
    return renderDetailsBox(`box ${role === "assistant" ? "assistant" : "user"}`, role.toUpperCase(), (list || []).map(renderContentBlock).join(""), {
      preview,
      tag: stop ? `<span class="summary-tag">[${esc(stop)}]</span>` : "",
      rawValue: rawValue ?? { role, content: list || [] },
    });
  };

  const renderTools = (tools) => renderDetailsBox("box panel", `${label("available_tools", "Available Tools")} (${tools.length})`, tools.map((tool) => `<div class="tool-card">${renderKv("name", renderPill(tool.name || "unknown"))}${renderKv("description", `<div class="tool-desc">${esc(tool.description || "No description")}</div>`)}${renderToolSchema(label("input_schema", "Input Schema"), tool.input_schema || {})}</div>`).join(""), { rawValue: tools });

  const setAll = (open) => detailsEl.querySelectorAll("details").forEach((node) => {
    node.open = open;
  });

  const normalizeUsage = (body) => {
    if (!body || typeof body !== "object") return null;

    const source = body.usage && typeof body.usage === "object" ? body.usage : null;
    const tokenDetails = Array.isArray(body.copilot_usage?.token_details) ? body.copilot_usage.token_details : [];
    const sumTokenType = (name) => tokenDetails
      .filter((item) => item?.token_type === name)
      .reduce((sum, item) => sum + (Number(item?.token_count) || 0), 0);

    const normalized = {
      input_tokens: 0,
      output_tokens: 0,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0,
      reasoning_tokens: 0,
    };

    if (source) {
      normalized.input_tokens = Number(
        source.input_tokens
          ?? source.prompt_tokens
          ?? 0
      ) || 0;
      normalized.output_tokens = Number(
        source.output_tokens
          ?? source.completion_tokens
          ?? 0
      ) || 0;
      normalized.cache_creation_input_tokens = Number(
        source.cache_creation_input_tokens
          ?? source.prompt_tokens_details?.cache_creation_tokens
          ?? 0
      ) || 0;
      normalized.cache_read_input_tokens = Number(
        source.cache_read_input_tokens
          ?? source.prompt_tokens_details?.cached_tokens
          ?? 0
      ) || 0;
      normalized.reasoning_tokens = Number(source.reasoning_tokens ?? 0) || 0;
      if ("server_tool_use" in source) normalized.server_tool_use = source.server_tool_use;
      if ("service_tier" in source) normalized.service_tier = source.service_tier;
    }

    if (!normalized.input_tokens) normalized.input_tokens = sumTokenType("input");
    if (!normalized.output_tokens) normalized.output_tokens = sumTokenType("output");
    if (!normalized.cache_read_input_tokens) normalized.cache_read_input_tokens = sumTokenType("cache_read");
    if (!normalized.cache_creation_input_tokens) normalized.cache_creation_input_tokens = sumTokenType("cache_creation");

    const hasValues = normalized.input_tokens
      || normalized.output_tokens
      || normalized.cache_creation_input_tokens
      || normalized.cache_read_input_tokens
      || normalized.reasoning_tokens
      || tokenDetails.length
      || source;

    return hasValues ? normalized : null;
  };
  const usage = (req) => normalizeUsage(getRespBody(req));
  const fmtTok = (value) => (!value ? "0" : value >= 1e6 ? `${(value / 1e6).toFixed(1)}M` : value >= 1e3 ? `${(value / 1e3).toFixed(1)}k` : String(value));
  const fmtDur = (ms) => (ms == null ? "" : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`);
  const fmtBytes = (value) => (!value ? "0B" : value >= 1024 * 1024 ? `${(value / (1024 * 1024)).toFixed(1)}MB` : value >= 1024 ? `${(value / 1024).toFixed(1)}KB` : `${value}B`);
  const shortText = (value, max = 30) => {
    const text = String(value ?? "");
    return text.length > max ? `${text.slice(0, Math.max(1, max - 1))}\u2026` : text;
  };
  const requestBody = (req) => (getReqBody(req) && typeof getReqBody(req) === "object" ? getReqBody(req) : {});
  const requestHeaders = (req) => (req?.request_headers && typeof req.request_headers === "object" ? req.request_headers : {});
  const responseHeaders = (req) => (req?.response_headers && typeof req.response_headers === "object" ? req.response_headers : {});
  const headerValue = (headers, name) => {
    const target = String(name || "").toLowerCase();
    for (const [key, value] of Object.entries(headers || {})) {
      if (String(key).toLowerCase() === target) return value;
    }
    return null;
  };
  const asNumber = (value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  };
  const requestSize = (req) => {
    const contentLength = asNumber(headerValue(requestHeaders(req), "content-length"));
    if (contentLength) return contentLength;
    const body = getReqBody(req);
    return body == null ? 0 : JSON.stringify(body).length;
  };
  const responseSize = (req) => {
    const contentLength = asNumber(headerValue(responseHeaders(req), "content-length"));
    if (contentLength) return contentLength;
    const raw = getRawResponse(req);
    if (raw) return raw.length;
    const body = getRespBody(req);
    return body == null ? 0 : JSON.stringify(body).length;
  };
  const bodyMessages = (req) => Array.isArray(requestBody(req).messages) ? requestBody(req).messages.length : 0;
  const bodyTools = (req) => Array.isArray(requestBody(req).tools) ? requestBody(req).tools.length : 0;
  const systemBlocks = (req) => {
    const system = requestBody(req).system;
    if (typeof system === "string" && system) return 1;
    return Array.isArray(system) ? system.length : 0;
  };
  const eventCount = (req) => Array.isArray(getSseEvents(req)) ? getSseEvents(req).length : 0;
  const isError = (req) => Boolean(req?.error) || getRespBody(req)?.type === "error";
  const tagsText = (req) => Array.isArray(req?.tags) && req.tags.length ? req.tags.join(",") : "";
  const inTok = (req) => {
    const data = usage(req);
    return data ? ((data.input_tokens || 0) + (data.cache_read_input_tokens || 0) + (data.cache_creation_input_tokens || 0)) : 0;
  };
  const outTok = (req) => {
    const data = usage(req);
    return data ? (data.output_tokens || 0) : 0;
  };

  function setConnectionState(nextState) {
    socketState = nextState;
    const stateClass = nextState === "Connected" ? "online" : nextState === "Connecting" ? "" : "offline";
    connectionStateEl.className = "signal" + (stateClass ? ` ${stateClass}` : "");
    connectionStateEl.title = nextState;
    updateHeader();
  }

  function updateHeader() {
    const items = [...requests.values()];
    const totalIn = items.reduce((sum, req) => sum + inTok(req), 0);
    const totalOut = items.reduce((sum, req) => sum + outTok(req), 0);
    const totalMessages = items.reduce((sum, req) => sum + bodyMessages(req), 0);
    const totalTools = items.reduce((sum, req) => sum + bodyTools(req), 0);
    const totalSystemBlocks = items.reduce((sum, req) => sum + systemBlocks(req), 0);
    const totalEvents = items.reduce((sum, req) => sum + eventCount(req), 0);
    const streamingCount = items.filter((req) => isStreaming(req)).length;
    const errorCount = items.filter((req) => isError(req)).length;
    const trackedCount = items.filter((req) => Array.isArray(req?.tags) && req.tags.includes("tracked")).length;
    const catchAllCount = items.filter((req) => Array.isArray(req?.tags) && req.tags.includes("catch-all")).length;
    const uniqueHosts = new Set(items.map((req) => req?.host).filter(Boolean)).size;
    const item = selectedId ? requests.get(selectedId) : null;
    if (!item) {
      metaEl.innerHTML = `<span class="stat dim">${esc(socketState)}</span><span class="sep">|</span><span class="stat dim">${items.length} req</span><span class="sep">|</span><span class="stat cyan">${uniqueHosts} host</span><span class="sep">|</span><span class="stat dim">${totalMessages} msg</span><span class="sep">|</span><span class="stat dim">${totalTools} tool</span><span class="sep">|</span><span class="stat dim">${totalSystemBlocks} sys</span><span class="sep">|</span><span class="stat cyan">${streamingCount} stream</span><span class="sep">|</span><span class="stat orange">${totalEvents} sse</span><span class="sep">|</span><span class="stat green">${trackedCount} tracked</span><span class="sep">|</span><span class="stat dim">${catchAllCount} catch</span><span class="sep">|</span><span class="stat orange">${errorCount} err</span><span class="sep">|</span><span class="stat blue">&uarr; ${esc(fmtTok(totalIn))}</span><span class="sep">|</span><span class="stat green">&darr; ${esc(fmtTok(totalOut))}</span>`;
      return;
    }
    const data = usage(item);
    const body = requestBody(item);
    const model = esc(body.model || "unknown");
    const msgCount = bodyMessages(item);
    const toolCount = bodyTools(item);
    const sysCount = systemBlocks(item);
    const sseCount = eventCount(item);
    const statusCode = item?.status_code ?? "--";
    const method = shortText(item?.method || "?", 8);
    const host = shortText(item?.host || "unknown", 24);
    const path = shortText(item?.path || "/", 26);
    const reqBytes = requestSize(item);
    const respBytes = responseSize(item);
    const streamLabel = isStreaming(item) ? "stream" : "buffered";
    const tagLabel = tagsText(item);
    const duration = fmtDur(getDuration(item));
    const cacheRead = data?.cache_read_input_tokens || 0;
    const cacheWrite = data?.cache_creation_input_tokens || 0;
    const plainIn = data?.input_tokens || 0;
    let html = `<span class="stat cyan">${esc(method)}</span><span class="sep">|</span><span class="stat dim">${esc(host)}</span><span class="sep">|</span><span class="stat dim">${esc(path)}</span><span class="sep">|</span><span class="stat ${statusCode >= 400 ? "orange" : "green"}">${esc(statusCode)}</span><span class="sep">|</span><span class="stat green">${model}</span><span class="sep">|</span><span class="stat dim">${msgCount} msg</span><span class="sep">|</span><span class="stat dim">${toolCount} tool</span><span class="sep">|</span><span class="stat dim">${sysCount} sys</span><span class="sep">|</span><span class="stat ${isStreaming(item) ? "cyan" : "dim"}">${streamLabel}</span>`;
    if (sseCount) {
      html += `<span class="sep">|</span><span class="stat orange">${sseCount} sse</span>`;
    }
    if (tagLabel) {
      html += `<span class="sep">|</span><span class="stat dim">${esc(tagLabel)}</span>`;
    }
    html += `<span class="sep">|</span><span class="stat blue">req ${esc(fmtBytes(reqBytes))}</span><span class="sep">|</span><span class="stat green">resp ${esc(fmtBytes(respBytes))}</span>`;
    if (duration) {
      html += `<span class="sep">|</span><span class="stat dim">${duration}</span>`;
    }
    if (isError(item)) {
      html += `<span class="sep">|</span><span class="stat orange">error</span>`;
    }
    if (data) {
      html += `<span class="sep">|</span><span class="stat blue">&uarr; ${fmtTok(inTok(item))}</span>`;
      if (cacheRead || cacheWrite || plainIn) {
        html += `<span class="stat dim">(</span>`;
        if (cacheRead) html += `<span class="stat green">${fmtTok(cacheRead)}</span>`;
        if (cacheRead && cacheWrite) html += `<span class="stat dim">+</span>`;
        if (cacheWrite) html += `<span class="stat orange">${fmtTok(cacheWrite)}</span>`;
        if ((cacheRead || cacheWrite) && plainIn) html += `<span class="stat dim">+</span>`;
        if (plainIn) html += `<span class="stat dim">${fmtTok(plainIn)}</span>`;
        html += `<span class="stat dim">)</span>`;
      }
      html += `<span class="sep">|</span><span class="stat green">&darr; ${fmtTok(outTok(item))}</span>`;
    } else {
      html += `<span class="sep">|</span><span class="stat blue">&uarr; ${fmtTok(totalIn)}</span><span class="sep">|</span><span class="stat green">&darr; ${fmtTok(totalOut)}</span>`;
    }
    metaEl.innerHTML = html;
  }

  function syncJsonModeButton() {
    jsonModeBtn.classList.toggle("active", jsonMode);
    jsonModeBtn.textContent = jsonMode ? "JSON On" : "JSON";
    jsonModeBtn.title = jsonMode ? "Showing raw JSON without UI transformations" : "Show raw JSON without UI transformations";
    jsonModeBtn.setAttribute("aria-pressed", jsonMode ? "true" : "false");
  }

  function renderList() {
    const items = [...requests.values()].sort((a, b) => b.timestamp - a.timestamp);
    const totalIn = items.reduce((sum, req) => sum + inTok(req), 0);
    requestsTotalEl.innerHTML = `&uarr; ${esc(fmtTok(totalIn))}`;
    if (!items.length) {
      listEl.innerHTML = '<div class="empty">No requests yet</div>';
      return;
    }
    listEl.innerHTML = items.map((item) => {
      const duration = fmtDur(getDuration(item)) || "--";
      const time = new Date(item.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      return `<button class="item ${item.id === selectedId ? "active" : ""}" data-id="${item.id}"><div class="item-top"><span class="item-model">${esc(getReqBody(item)?.model || "unknown")}</span><span class="item-usage"><span class="item-flow in">&uarr; ${esc(fmtTok(inTok(item)))}</span><span class="item-flow out">&darr; ${esc(fmtTok(outTok(item)))}</span></span></div><div class="item-bottom"><span class="item-time">${esc(time)}</span><span class="item-duration">${esc(duration)}</span></div></button>`;
    }).join("");
    listEl.querySelectorAll(".item").forEach((node) => node.addEventListener("click", () => {
      selectedId = node.dataset.id;
      renderList();
      renderDetails();
    }));
  }

  function renderSetup() {
    detailsEl.innerHTML = `<section class="setup"><div class="setup-inner"><h2>[CLI TRACKER]</h2><p class="setup-tag">Capture & visualize <strong>CLI traffic</strong></p><div class="os-tabs"><button class="os-tab active" data-os="windows" type="button">Windows</button><button class="os-tab" data-os="linux" type="button">Linux</button><button class="os-tab" data-os="macos" type="button">macOS</button></div><div class="client-tabs"><button class="client-tab active" data-client="claude" type="button">Claude</button><button class="client-tab" data-client="opencode" type="button">OpenCode</button></div><div class="step-card primary"><div><span class="step-num">01</span><span class="step-title">Configure Terminal</span></div><div class="step-copy">Run this in any terminal to route traffic through the proxy.</div><span class="cmd-label">Setup Command</span><div class="cmd-wrap"><span class="prompt">$</span><code id="setup-command"></code><button class="copy-btn" id="copy-setup" title="Copy command" type="button">Copy</button></div></div><div class="step-card"><div><span class="step-num">02</span><span class="step-title" id="client-title">Launch Claude</span></div><div class="step-copy" id="client-copy">Start Claude Code in the same terminal.</div><span class="cmd-label">Run</span><div class="cmd-wrap"><span class="prompt">$</span><code id="client-command">claude</code></div></div><div class="step-card cert-help hidden" id="windows-cert-help"><div><span class="step-num">03</span><span class="step-title">Fix Windows Certificate Trust</span></div><div class="step-copy">Crush and other Go clients on Windows use the system certificate store, so environment variables like <span class="mono">SSL_CERT_FILE</span> are ignored. Import the mitmproxy CA into trusted root certificates.</div><span class="cmd-label">PowerShell (Admin)</span><div class="cmd-wrap multiline"><span class="prompt">$</span><code>Import-Certificate -FilePath "$env:USERPROFILE\\.mitmproxy\\mitmproxy-ca-cert.pem" -CertStoreLocation Cert:\\LocalMachine\\Root</code><button class="copy-btn copy-inline-btn" type="button">Copy</button></div><span class="cmd-label">PowerShell (Current User)</span><div class="cmd-wrap multiline"><span class="prompt">$</span><code>Import-Certificate -FilePath "$env:USERPROFILE\\.mitmproxy\\mitmproxy-ca-cert.pem" -CertStoreLocation Cert:\\CurrentUser\\Root</code><button class="copy-btn copy-inline-btn" type="button">Copy</button></div><span class="cmd-label">Remove Later</span><div class="cmd-wrap multiline"><span class="prompt">$</span><code>Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like "*mitmproxy*" } | Remove-Item</code><button class="copy-btn copy-inline-btn" type="button">Copy</button></div><div class="setup-note">Adding the mitmproxy CA to Trusted Root Certification Authorities allows the local proxy to decrypt HTTPS traffic. Use it only if you intend to inspect local traffic.</div></div><div class="setup-hint"><code>proxy: http://localhost:${bootstrap.proxy_port}</code></div></div></section>`;

    const setupUrl = (os, client) => {
      const params = new URLSearchParams();
      params.set("client", client);
      if (os === "windows") {
        params.set("shell", "powershell");
      }
      return `${location.origin}/setup?${params.toString()}`;
    };

    const commands = {
      windows: (client) => `Invoke-Expression (Invoke-RestMethod "${setupUrl("windows", client)}")`,
      linux: (client) => `eval "$(curl -s ${setupUrl("linux", client)})"`,
      macos: (client) => `eval "$(curl -s ${setupUrl("macos", client)})"`,
    };
    const clients = {
      claude: { title: "Launch Claude", copy: "Start Claude Code in the same terminal.", command: "claude" },
      opencode: { title: "Launch OpenCode", copy: "Start OpenCode in the same terminal.", command: "opencode" },
    };

    const commandEl = detailsEl.querySelector("#setup-command");
    const copyBtn = detailsEl.querySelector("#copy-setup");
    const tabs = [...detailsEl.querySelectorAll(".os-tab")];
    const clientTabs = [...detailsEl.querySelectorAll(".client-tab")];
    const clientTitleEl = detailsEl.querySelector("#client-title");
    const clientCopyEl = detailsEl.querySelector("#client-copy");
    const clientCommandEl = detailsEl.querySelector("#client-command");
    const windowsCertHelpEl = detailsEl.querySelector("#windows-cert-help");
    let currentOs = "windows";
    let currentClient = "claude";

    const syncSetup = () => {
      tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.os === currentOs));
      clientTabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.client === currentClient));
      commandEl.textContent = (commands[currentOs] || commands.windows)(currentClient);
      const clientConfig = clients[currentClient] || clients.claude;
      clientTitleEl.textContent = clientConfig.title;
      clientCopyEl.textContent = clientConfig.copy;
      clientCommandEl.textContent = clientConfig.command;
      windowsCertHelpEl.classList.toggle("hidden", currentOs !== "windows");
    };

    tabs.forEach((tab) => tab.addEventListener("click", () => {
      currentOs = tab.dataset.os || "windows";
      syncSetup();
    }));
    clientTabs.forEach((tab) => tab.addEventListener("click", () => {
      currentClient = tab.dataset.client || "claude";
      syncSetup();
    }));
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(commandEl.textContent || "");
        copyBtn.textContent = "Copied";
      } catch {
        copyBtn.textContent = "Failed";
      }
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1200);
    });
    attachInlineCopyHandlers(detailsEl);

    syncSetup();
  }

  function renderDetails() {
    jsonBlockSeq = 0;
    rawJsonStore.clear();
    if (!requests.size) {
      renderSetup();
      updateHeader();
      return;
    }
    const item = selectedId ? requests.get(selectedId) : null;
    if (!item) {
      detailsEl.innerHTML = '<div class="empty">Select a request</div>';
      updateHeader();
      return;
    }
    if (jsonMode) {
      detailsEl.innerHTML = renderJsonMode(item);
      updateHeader();
      return;
    }

    const body = getReqBody(item) || {};
    const response = getRespBody(item);
    const messages = Array.isArray(body.messages) ? body.messages : [];
    let html = "";
    if (body.system) html += renderSystem(body.system);
    if (Array.isArray(body.tools) && body.tools.length) html += renderTools(body.tools);
    html += messages.map((message) => renderMsg(message.role || "user", blocks(message), "", message)).join("");

    if (response) {
      if (response.type === "error") {
        const errorText = response.error?.message || "";
        const errorType = response.error?.type || "error";
        html += renderDetailsBox("box assistant", label("assistant_error", "ASSISTANT (ERROR)"), `<div class="error-box"><div class="error-type">${esc(errorType)}</div><div class="error-msg">${esc(errorText)}</div></div>`, {
          preview: compactText(errorText),
          rawValue: response,
        });
      } else {
        html += renderMsg("assistant", Array.isArray(response.content) ? response.content : [], response.stop_reason || "", response);
      }
    } else if (getRawResponse(item)) {
      html += renderDetailsBox("box assistant", label("assistant", "ASSISTANT"), renderPre(getRawResponse(item)), {
        preview: compactText(getRawResponse(item)),
        rawValue: getRawResponse(item),
      });
    }

    if (isStreaming(item) && getSseEvents(item).length) {
      html += renderDetailsBox("box panel", label("streaming_events", "Streaming Events"), renderPre(getSseEvents(item)), {
        preview: `${getSseEvents(item).length} ${label("events", "events")}`,
        rawValue: getSseEvents(item),
      });
    }

    html += renderRawRequest(body);
    detailsEl.innerHTML = html;
    hydrateJsonViews();
    updateHeader();
  }

  ws.onopen = () => setConnectionState("Connected");
  ws.onclose = () => setConnectionState("Disconnected");
  ws.onerror = () => setConnectionState("Connection error");
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "diagnostics_update") {
      if (liveDiagnosticsEl.checked && message.diagnostics) {
        settingsData = {
          ...settingsData,
          ...message.diagnostics,
        };
        renderDiagnostics();
      }
      return;
    }
    if (message.type === "history_sync") {
      requests.clear();
      for (const item of message.requests) mergeRequest(item);
      if (!selectedId && message.requests.length) selectedId = message.requests[message.requests.length - 1].id;
    } else if (message.request) {
      const merged = mergeRequest(message.request);
      if (!selectedId && merged) selectedId = merged.id;
    } else if (message.type === "clear_all") {
      requests.clear();
      selectedId = null;
    }
    renderList();
    renderDetails();
  };

  document.getElementById("clear").addEventListener("click", () => {
    clearRequests().catch(() => {
      connectionStateEl.title = "Failed to clear requests";
    });
  });
  collapseSettingsBtn.addEventListener("click", toggleSettingsCollapse);
  window.addEventListener("resize", syncSettingsPanel);
  liveDiagnosticsEl.addEventListener("change", () => {
    if (liveDiagnosticsEl.checked) {
      loadSettings().catch(() => setStatus("Live diagnostics paused", "warn"));
    }
  });
  diagnosticTabsEl.querySelectorAll(".diag-tab").forEach((button) => {
    button.addEventListener("click", () => {
      activeDiagnosticTab = button.dataset.tab || "hosts";
      renderDiagnostics();
    });
  });
  document.getElementById("save-settings").addEventListener("click", () => {
    saveSettings().catch(() => setStatus("Failed to save", "warn"));
  });
  document.getElementById("refresh-debug").addEventListener("click", () => {
    loadSettings().catch(() => setStatus("Failed to load", "warn"));
  });
  document.getElementById("clear-debug").addEventListener("click", () => {
    clearRejected().catch(() => setStatus("Failed to clear", "warn"));
  });
  jsonModeBtn.addEventListener("click", () => {
    jsonMode = !jsonMode;
    localStorage.setItem("wiretap-json-mode", jsonMode ? "1" : "0");
    syncJsonModeButton();
    renderDetails();
  });
  document.getElementById("expand-all").addEventListener("click", () => setAll(true));
  document.getElementById("collapse-all").addEventListener("click", () => setAll(false));
  attachInlineCopyHandlers(settingsPanelEl);
  detailsEl.addEventListener("click", (event) => {
    const button = event.target.closest(".summary-json-btn");
    if (!button) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const targetId = button.dataset.jsonTarget;
    if (!targetId) {
      return;
    }
    const box = button.closest(".json-enabled");
    const panel = box?.querySelector(`#${targetId}`);
    const content = box?.querySelector(".json-content-view");
    if (!panel) {
      return;
    }
    const isHidden = panel.classList.contains("hidden");
    if (content) {
      content.classList.toggle("hidden", isHidden);
    }
    panel.classList.toggle("hidden", !isHidden);
    button.classList.toggle("active", isHidden);
    button.setAttribute("aria-pressed", isHidden ? "true" : "false");
    button.textContent = isHidden ? "Hide JSON" : "JSON";
  });
  syncJsonModeButton();
  syncSettingsPanel();
  setConnectionState("Connecting");
  loadSettings().catch(() => setStatus("Failed to load", "warn"));
  renderList();
  renderDetails();
})();
