/**
 * DDoS Defense SOC Real-Time Dashboard Client
 * 
 * Enforces:
 * - First-message WebSocket authentication (connect, then send {"type": "auth", "key": "..."})
 * - sessionStorage or in-memory ONLY for DDOS_ADMIN_KEYS
 * - Server-to-client WS telemetry streaming
 * - REST-only gated approve/reject execution via /actions/approve and /actions/reject
 */

(function () {
  "use strict";

  // Key storage: Condition 4: sessionStorage only
  const AUTH_STORAGE_KEY = "ddos_operator_key";
  function getStoredKey() {
    return window.sessionStorage.getItem(AUTH_STORAGE_KEY) || "";
  }
  function setStoredKey(key) {
    window.sessionStorage.setItem(AUTH_STORAGE_KEY, key.trim());
  }

  // DOM elements
  const connectionBadge = document.getElementById("connectionBadge");
  const connectionText = document.getElementById("connectionText");
  const adminKeyInput = document.getElementById("adminKeyInput");
  const saveKeyBtn = document.getElementById("saveKeyBtn");
  const authStatusText = document.getElementById("authStatusText");
  const flowRateVal = document.getElementById("flowRateVal");
  const totalFlowsVal = document.getElementById("totalFlowsVal");
  const totalAttacksVal = document.getElementById("totalAttacksVal");
  const pendingCountVal = document.getElementById("pendingCountVal");
  const taxonomyList = document.getElementById("taxonomyList");
  const actionsTbody = document.getElementById("actionsTbody");
  const actionFeedback = document.getElementById("actionFeedback");
  const refreshActionsBtn = document.getElementById("refreshActionsBtn");
  const flowFeed = document.getElementById("flowFeed");
  const flowCanvas = document.getElementById("flowCanvas");

  // State
  let ws = null;
  let flowRateHistory = new Array(30).fill(0);
  let attackHistory = new Array(30).fill(0);
  let pendingActionsMap = new Map();
  let taxonomyCounts = {};
  let reconnectTimer = null;

  // Initialize key input
  const initialKey = getStoredKey();
  if (initialKey) {
    adminKeyInput.value = initialKey;
    authStatusText.textContent = "Key configured in sessionStorage";
    authStatusText.style.color = "var(--color-success)";
  }

  saveKeyBtn.addEventListener("click", () => {
    const val = adminKeyInput.value.trim();
    if (val) {
      setStoredKey(val);
      authStatusText.textContent = "Key saved in sessionStorage";
      authStatusText.style.color = "var(--color-success)";
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
      } else {
        // Re-authenticate if socket was disconnected
        ws.close();
      }
    }
  });

  refreshActionsBtn.addEventListener("click", () => {
    fetchPendingActions();
  });

  // Canvas Flow Rate Chart
  const ctx = flowCanvas ? flowCanvas.getContext("2d") : null;
  function resizeCanvas() {
    if (!flowCanvas) return;
    flowCanvas.width = flowCanvas.parentElement.clientWidth;
    flowCanvas.height = flowCanvas.parentElement.clientHeight;
  }
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  function renderChart() {
    if (!ctx || !flowCanvas) return;
    const w = flowCanvas.width;
    const h = flowCanvas.height;
    ctx.clearRect(0, 0, w, h);

    // Background grid
    ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const maxVal = Math.max(10, ...flowRateHistory, ...attackHistory);
    const step = w / (flowRateHistory.length - 1);

    // Draw attack spikes (bars/fill)
    ctx.fillStyle = "rgba(239, 68, 68, 0.15)";
    for (let i = 0; i < attackHistory.length; i++) {
      if (attackHistory[i] > 0) {
        const x = i * step;
        const barH = (attackHistory[i] / maxVal) * (h - 20);
        ctx.fillRect(x - step / 2, h - barH, step, barH);
      }
    }

    // Draw flow rate line
    ctx.beginPath();
    ctx.strokeStyle = "#06B6D4";
    ctx.lineWidth = 2.5;
    for (let i = 0; i < flowRateHistory.length; i++) {
      const x = i * step;
      const y = h - (flowRateHistory[i] / maxVal) * (h - 30) - 10;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Fill under line
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "rgba(6, 182, 212, 0.2)");
    grad.addColorStop(1, "rgba(6, 182, 212, 0.0)");
    ctx.fillStyle = grad;
    ctx.fill();
  }

  // WebSocket Connection Lifecycle
  function connectWebSocket() {
    if (reconnectTimer) clearTimeout(reconnectTimer);

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/dashboard`;

    updateConnectionStatus("CONNECTING...", "disconnected");

    try {
      ws = new WebSocket(wsUrl);
    } catch (e) {
      console.error("WS connection error:", e);
      scheduleReconnect();
      return;
    }

    ws.onopen = function () {
      // Condition 1: Connect unauthenticated, then send {"type": "auth", "key": "..."} as first message
      const key = getStoredKey() || "dev-admin-key";
      ws.send(JSON.stringify({ type: "auth", key: key }));
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        handleWsMessage(data);
      } catch (err) {
        console.error("Failed to parse WS payload:", err);
      }
    };

    ws.onerror = function (err) {
      console.warn("WebSocket error:", err);
    };

    ws.onclose = function (evt) {
      if (evt.code === 1008) {
        updateConnectionStatus("AUTH FAILED (1008)", "disconnected");
        authStatusText.textContent = "Authentication rejected (code 1008). Check DDOS_ADMIN_KEYS / API_KEYS.";
        authStatusText.style.color = "var(--color-danger)";
      } else {
        updateConnectionStatus("DISCONNECTED", "disconnected");
      }
      scheduleReconnect();
    };
  }

  function scheduleReconnect() {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(() => {
      connectWebSocket();
    }, 4000);
  }

  function updateConnectionStatus(text, className) {
    if (connectionText) connectionText.textContent = text;
    if (connectionBadge) {
      connectionBadge.className = `status-badge ${className}`;
    }
  }

  function handleWsMessage(msg) {
    switch (msg.type) {
      case "auth_ok":
        updateConnectionStatus("CONNECTED", "connected");
        authStatusText.textContent = "Authenticated successfully";
        authStatusText.style.color = "var(--color-success)";
        break;

      case "initial_state":
        if (msg.flow_rate !== undefined) flowRateVal.textContent = msg.flow_rate.toFixed(1);
        if (msg.total_flows !== undefined) totalFlowsVal.textContent = msg.total_flows.toLocaleString();
        if (msg.total_attacks !== undefined) totalAttacksVal.textContent = msg.total_attacks.toLocaleString();
        if (msg.pending_count !== undefined) pendingCountVal.textContent = msg.pending_count;

        if (msg.taxonomy_counts) {
          taxonomyCounts = msg.taxonomy_counts;
          renderTaxonomy();
        }
        if (msg.pending_actions) {
          populatePendingActions(msg.pending_actions);
        }
        if (msg.recent_flows) {
          msg.recent_flows.slice(-10).forEach(addFlowToFeed);
        }
        break;

      case "flow_scored":
        if (msg.flow_rate !== undefined) flowRateVal.textContent = msg.flow_rate.toFixed(1);
        if (msg.total_flows !== undefined) totalFlowsVal.textContent = msg.total_flows.toLocaleString();
        if (msg.total_attacks !== undefined) totalAttacksVal.textContent = msg.total_attacks.toLocaleString();

        const flow = msg.flow || {};
        const isAttack = Boolean(flow.is_attack);
        const rate = msg.flow_rate || 0;

        flowRateHistory.push(rate);
        flowRateHistory.shift();
        attackHistory.push(isAttack ? rate * 0.8 : 0);
        attackHistory.shift();
        renderChart();

        if (flow.label) {
          taxonomyCounts[flow.label] = (taxonomyCounts[flow.label] || 0) + (msg.batch_size || 1);
          renderTaxonomy();
        }

        addFlowToFeed(flow);
        break;

      case "burst_alert":
        if (msg.alert) {
          const alert = msg.alert;
          showFeedback(`🚨 High-Priority Alert: ${alert.attack_type} from ${alert.attacker_ip} (Conf: ${(alert.confidence || 0).toFixed(2)})`, "error");
          fetchPendingActions();
        }
        break;

      case "pending_update":
        if (msg.pending_count !== undefined) {
          pendingCountVal.textContent = msg.pending_count;
        }
        if (msg.pending_actions) {
          populatePendingActions(msg.pending_actions);
        }
        break;

      default:
        break;
    }
  }

  function renderTaxonomy() {
    if (!taxonomyList) return;
    taxonomyList.innerHTML = "";
    const entries = Object.entries(taxonomyCounts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
      taxonomyList.innerHTML = `<div class="empty-hint">Awaiting flow telemetry...</div>`;
      return;
    }

    const total = entries.reduce((acc, curr) => acc + curr[1], 0) || 1;
    entries.forEach(([label, count]) => {
      const pct = ((count / total) * 100).toFixed(1);
      const isBenign = label.toLowerCase() === "benign";
      const item = document.createElement("div");
      item.className = "taxonomy-item";
      item.innerHTML = `
        <div class="tax-row">
          <span>${label}</span>
          <span>${count} (${pct}%)</span>
        </div>
        <div class="tax-bar-wrap">
          <div class="tax-bar-fill ${isBenign ? "benign" : "attack"}" style="width: ${pct}%"></div>
        </div>
      `;
      taxonomyList.appendChild(item);
    });
  }

  function addFlowToFeed(flow) {
    if (!flowFeed || !flow) return;
    const isAttack = Boolean(flow.is_attack);
    const label = flow.label || (isAttack ? "Attack" : "Benign");
    const conf = flow.confidence !== undefined ? flow.confidence.toFixed(2) : "1.00";
    const consensus = flow.consensus_tier || "";

    const item = document.createElement("div");
    item.className = `feed-item ${isAttack ? "attack" : "benign"}`;
    item.innerHTML = `
      <div>
        <strong>${label}</strong>
        ${consensus ? `<span class="badge ${getConsensusBadgeClass(consensus)}" style="margin-left:6px">${consensus}</span>` : ""}
      </div>
      <div>Conf: ${conf} | ${new Date().toLocaleTimeString()}</div>
    `;

    flowFeed.prepend(item);
    while (flowFeed.children.length > 25) {
      flowFeed.removeChild(flowFeed.lastChild);
    }
  }

  function getConsensusBadgeClass(status) {
    if (status === "FULL_UNANIMOUS" || status === "TABULAR_UNANIMOUS") return "badge-unanimous";
    if (status === "TABULAR_UNANIMOUS_SEQUENCE_DISSENT") return "badge-dissent";
    if (status === "SINGLE_MODEL") return "badge-single";
    if (status && status.includes("SPLIT")) return "badge-split";
    return "badge-single";
  }

  function populatePendingActions(actions) {
    if (!actionsTbody) return;
    pendingActionsMap.clear();
    actions.forEach(a => pendingActionsMap.set(a.action_id, a));

    if (actions.length === 0) {
      actionsTbody.innerHTML = `<tr><td colspan="6" class="empty-row">No pending actions in queue. System secure.</td></tr>`;
      pendingCountVal.textContent = "0";
      return;
    }

    pendingCountVal.textContent = actions.length;
    actionsTbody.innerHTML = "";

    actions.forEach(action => {
      const tr = document.createElement("tr");

      // Extract consensus, breakdown & caveat context
      const breakdown = action.per_model_breakdown || {};
      const consensusTier = action.consensus_tier || breakdown.mode || "PROPOSED";
      const consensusSummary = action.consensus_summary || action.reason || "";
      const caveat = action.caveat || (breakdown.sequence_classifier && breakdown.sequence_classifier.caveat) || "";

      // Model chips
      const chips = [];
      if (breakdown.random_forest) {
        chips.push(`<span class="model-chip">RF: ${breakdown.random_forest.label} (${(breakdown.random_forest.confidence || 0).toFixed(2)})</span>`);
      }
      if (breakdown.xgboost) {
        chips.push(`<span class="model-chip">XGB: ${breakdown.xgboost.label} (${(breakdown.xgboost.confidence || 0).toFixed(2)})</span>`);
      }
      if (breakdown.sequence_classifier && breakdown.sequence_classifier.active) {
        chips.push(`<span class="model-chip">LSTM: ${breakdown.sequence_classifier.label} (${(breakdown.sequence_classifier.confidence || 0).toFixed(2)})</span>`);
      }

      const consensusHtml = `
        <div class="consensus-container">
          <div><span class="badge ${getConsensusBadgeClass(consensusTier)}">${consensusTier}</span></div>
          ${chips.length > 0 ? `<div class="breakdown-chips">${chips.join("")}</div>` : ""}
          ${caveat ? `<div class="caveat-callout"><span>⚠️</span> <span>${caveat}</span></div>` : ""}
        </div>
      `;

      tr.innerHTML = `
        <td>
          <div class="action-target">
            <span class="target-ips">${action.attacker_ip} &rarr; ${action.victim_ip}</span>
            <div class="action-id-tag">ID: ${action.action_id}</div>
          </div>
        </td>
        <td>
          <span class="badge badge-vector">${action.action_type || "DDoS"}</span>
        </td>
        <td>
          <strong style="color:var(--color-danger)">${(action.confidence || 0).toFixed(2)}</strong>
          <div style="font-size:11px; color:var(--text-muted)">High Blast-Radius</div>
        </td>
        <td>${consensusHtml}</td>
        <td>
          <code style="font-size:11px; color:var(--text-secondary); background:rgba(0,0,0,0.3); padding:4px 6px; border-radius:4px; display:inline-block">
            ${(action.commands && action.commands[0]) || "DROP attacker flow"}
          </code>
        </td>
        <td class="text-right">
          <div class="btn-group">
            <button class="btn btn-approve" data-id="${action.action_id}">Approve</button>
            <button class="btn btn-reject" data-id="${action.action_id}">Reject</button>
          </div>
        </td>
      `;

      // Attach button event handlers calling GATED REST endpoints
      tr.querySelector(".btn-approve").addEventListener("click", () => handleApproveAction(action.action_id));
      tr.querySelector(".btn-reject").addEventListener("click", () => handleRejectAction(action.action_id));

      actionsTbody.appendChild(tr);
    });
  }

  // REST-Only Action Execution Gate
  async function handleApproveAction(actionId) {
    const adminKey = getStoredKey();
    if (!adminKey) {
      showFeedback("Admin key required! Enter DDOS_ADMIN_KEYS in header above.", "error");
      return;
    }

    try {
      const resp = await fetch(`/actions/approve/${encodeURIComponent(actionId)}`, {
        method: "POST",
        headers: {
          "X-Admin-Key": adminKey,
          "Content-Type": "application/json"
        }
      });
      const data = await resp.json();

      if (resp.ok) {
        showFeedback(`Action ${actionId} approved and executed successfully.`, "success");
        fetchPendingActions();
      } else {
        showFeedback(`Approval failed (${resp.status}): ${data.detail || JSON.stringify(data)}`, "error");
      }
    } catch (err) {
      showFeedback(`Approval network error: ${err.message}`, "error");
    }
  }

  async function handleRejectAction(actionId) {
    const adminKey = getStoredKey();
    if (!adminKey) {
      showFeedback("Admin key required! Enter DDOS_ADMIN_KEYS in header above.", "error");
      return;
    }

    try {
      const resp = await fetch(`/actions/reject/${encodeURIComponent(actionId)}`, {
        method: "POST",
        headers: {
          "X-Admin-Key": adminKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ reason: "Operator rejected via SOC dashboard" })
      });
      const data = await resp.json();

      if (resp.ok) {
        showFeedback(`Action ${actionId} rejected.`, "success");
        fetchPendingActions();
      } else {
        showFeedback(`Rejection failed (${resp.status}): ${data.detail || JSON.stringify(data)}`, "error");
      }
    } catch (err) {
      showFeedback(`Rejection network error: ${err.message}`, "error");
    }
  }

  async function fetchPendingActions() {
    const key = getStoredKey();
    const headers = key ? { "X-Admin-Key": key } : {};
    try {
      const resp = await fetch("/actions/pending", { headers });
      if (resp.ok) {
        const data = await resp.json();
        populatePendingActions(data.pending_actions || []);
      }
    } catch (e) {
      console.warn("Failed to fetch pending actions:", e);
    }
  }

  function showFeedback(text, type) {
    if (!actionFeedback) return;
    actionFeedback.textContent = text;
    actionFeedback.className = `action-feedback ${type}`;
    actionFeedback.classList.remove("hidden");
    setTimeout(() => {
      actionFeedback.classList.add("hidden");
    }, 6000);
  }

  // Start WebSocket client on load
  connectWebSocket();
})();
