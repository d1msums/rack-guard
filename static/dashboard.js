'use strict';
const el = id => document.getElementById(id);
const put = (id, value) => { const node = el(id); if (node) node.textContent = value; };
let events = [], latencies = [], polls = 0, successful = 0;
let seenAlerts = new Set(), previousInvalid = 0;
function notifySecurity(message) {
  put('security-banner-text', message); el('security-banner').hidden = false;
}
el('dismiss-security').addEventListener('click', () => {el('security-banner').hidden = true;});
function switchTab(name, node) {
  document.querySelectorAll('.content-area').forEach(item => item.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
  el(`tab-${name}`).classList.add('active'); node.classList.add('active');
  put('page-title', node.textContent.trim()); drawAll();
}
document.querySelectorAll('[data-tab]').forEach(node => {
  node.addEventListener('click', () => switchTab(node.dataset.tab, node));
  node.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') {e.preventDefault(); switchTab(node.dataset.tab, node);} });
});
function chart(id, points, unit) {
  const canvas = el(id), width = canvas.clientWidth;
  if (!width) return;
  const ratio = window.devicePixelRatio || 1, height = 250;
  canvas.width = width * ratio; canvas.height = height * ratio;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d'); ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height); ctx.font = '12px sans-serif'; ctx.fillStyle = '#d4d4d4';
  if (!points.length) {ctx.fillText('Awaiting measured data', 25, 40); return;}
  const values = points.map(p => p.value), low = Math.min(...values) - 1, high = Math.max(...values) + 1;
  const left = 52, right = width - 22, top = 20, bottom = height - 35;
  for (let i = 0; i <= 4; i++) {
    const y = top + (bottom - top) * i / 4;
    ctx.strokeStyle = '#ffffff25'; ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
    ctx.fillText((high - (high - low) * i / 4).toFixed(1), 4, y + 4);
  }
  ctx.strokeStyle = '#67e8f9'; ctx.lineWidth = 2; ctx.beginPath();
  points.forEach((p, i) => {
    const x = left + (right - left) * i / Math.max(1, points.length - 1);
    const y = bottom - (p.value - low) / (high - low) * (bottom - top);
    if (i) ctx.lineTo(x, y); else ctx.moveTo(x, y);
  }); ctx.stroke();
  ctx.fillText(`${points.length} samples · ${unit}`, left, height - 10);
  canvas.setAttribute('aria-label', `${unit} chart, ${points.length} samples, latest ${values.at(-1).toFixed(1)}`);
}
function drawAll() {
  chart('tempChart', events.filter(e => e.event_type === 'temperature').map(e => ({value:e.data.temperature_c})), '°C');
  chart('respTimeChart', latencies.map(value => ({value})), 'milliseconds');
}
function render(snapshot) {
  events = snapshot.events;
  const temp = events.filter(e => e.event_type === 'temperature').at(-1);
  const rfid = events.filter(e => e.event_type === 'rfid_scan').at(-1);
  put('temp-value', temp ? `${temp.data.temperature_c.toFixed(1)} °C` : '-- °C');
  put('temp-time', temp ? `Sensor time: ${new Date(temp.timestamp).toLocaleString()}` : 'No verified temperature in window');
  el('temp-sim').style.display = temp?.simulated ? 'inline-block' : 'none';
  put('rfid-value', rfid ? 'token-********' : '--');
  put('rfid-status', rfid ? (rfid.access_granted === true ? 'ACCESS GRANTED' : rfid.access_granted === false ? 'ACCESS DENIED' : 'UNKNOWN') : 'No scans');
  put('rfid-time', rfid ? `Scan time: ${new Date(rfid.timestamp).toLocaleString()}` : 'No verified RFID in window');
  el('rfid-sim').style.display = rfid?.simulated ? 'inline-block' : 'none';
  const age = temp ? (Date.parse(snapshot.server_time) - Date.parse(temp.timestamp)) / 1000 : Infinity;
  put('data-mode', !temp ? 'NO DATA' : age > 15 || age < -60 ? 'STALE' : 'FRESH');
  put('last-received', temp ? `Last received: ${new Date(temp.received_at).toLocaleString()}` : '--');
  put('proof-status', `${events.length} verified · ${snapshot.invalid_rows} invalid · ${snapshot.unverifiable_rows} without proof`);
  put('security-integrity', snapshot.invalid_rows ? `HIGH · Database integrity: ${snapshot.invalid_rows} invalid records in the latest ${snapshot.window_size} rows. Invalid rows were withheld. Investigate possible modification or corruption.` : 'Database integrity: no invalid signed records detected in the current window.');
  if (snapshot.invalid_rows > previousInvalid) notifySecurity(`Database integrity alert: ${snapshot.invalid_rows} invalid records in the current window.`);
  previousInvalid = snapshot.invalid_rows;
  put('alert-container', snapshot.invalid_rows ? 'Integrity alert: invalid database rows were withheld.' :
      !temp ? 'Waiting for verified temperature data.' : age > 15 ? 'Temperature data is stale. Check the Pi connection.' : '');
  const terminal = el('terminal'); terminal.replaceChildren();
  events.slice(-80).forEach(event => {
    const row = document.createElement('p');
    const value = event.event_type === 'temperature' ? `${event.data.temperature_c} °C` :
      event.access_granted === true ? 'ACCESS GRANTED' : event.access_granted === false ? 'ACCESS DENIED' : 'UNKNOWN';
    row.textContent = `${new Date(event.timestamp).toLocaleTimeString()} | ${event.event_type} | ${value} | seq ${event.sequence}${event.simulated ? ' | SIMULATED' : ''}`;
    terminal.appendChild(row);
  }); terminal.scrollTop = terminal.scrollHeight; drawAll();
}
async function getJSON(url) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(url, {credentials:'same-origin', cache:'no-store', signal:controller.signal});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {clearTimeout(timer);}
}
async function analysis() {
  try {
    const report = await getJSON('/api/analysis');
    put('ai-output', report.summary);
    put('ai-threat-level', report.status !== 'available' ? 'UNAVAILABLE' : report.stale ? 'STALE REPORT' : 'ADVISORY');
    put('ai-confidence', report.model || '--');
    put('ai-events-count', report.events_analyzed ?? '--');
    el('ai-output').classList.remove('typewriter');
    if (report.generated_at) put('ai-output', `${report.summary}\n\nGenerated: ${new Date(report.generated_at).toLocaleString()}\nAdvisory only; no access decisions or device actions executed.`);
  } catch (error) {put('ai-output', `Analysis unavailable (${error.message})`); put('ai-threat-level', 'UNAVAILABLE');}
}
async function pollAlerts() {
  try {
    const result = await getJSON('/api/alerts?limit=100');
    const alerts = result.alerts;
    put('security-count', String(alerts.length));
    put('security-feed-status', result.status === 'no_log_yet' ? 'No receiver rejection log yet. Coverage starts when the receiver writes a rejection.' :
      `${alerts.length} recent records loaded · ${result.skipped_lines} malformed/unsupported lines skipped${result.tail_limited ? ' · bounded tail of log' : ''} · Checked ${new Date(result.server_time).toLocaleTimeString()}`);
    const list = el('security-list'); list.replaceChildren();
    if (!alerts.length) {const row=document.createElement('p'); row.textContent='No supported rejection records in this window.'; list.appendChild(row);}
    alerts.forEach(alert => {
      const card = document.createElement('article');
      card.className = `security-row ${['high','warning','info'].includes(alert.severity) ? alert.severity : 'info'}`;
      const title = document.createElement('strong'); title.textContent = `${alert.severity.toUpperCase()} · ${alert.title}`;
      const time = document.createElement('p'); time.textContent = `${new Date(alert.received_at).toLocaleString()} · ${alert.reason}`;
      const description = document.createElement('p'); description.textContent = alert.description;
      card.append(title, time, description); list.appendChild(card);
    });
    // On first load, only recent high-priority records raise a banner. IDs prevent repeat notifications.
    const recentHigh = alerts.find(alert => {
      const age = (Date.parse(result.server_time) - Date.parse(alert.received_at)) / 1000;
      return alert.severity === 'high' && !seenAlerts.has(alert.id) && age >= -5 && age <= 90;
    });
    alerts.forEach(alert => seenAlerts.add(alert.id));
    if (seenAlerts.size > 500) seenAlerts = new Set([...seenAlerts].slice(-300));
    if (recentHigh) notifySecurity(`Suspicious activity · ${recentHigh.title}. Open Security Alerts for details.`);
  } catch (error) {
    put('security-feed-status', `Alert feed unavailable (${error.message}). Previous records may be old; do not interpret this as no alerts.`);
    put('security-count', '?');
  } finally {setTimeout(pollAlerts, 3000);}
}
pollAlerts();
async function poll() {
  const started = performance.now(); polls++;
  try {
    const snapshot = await getJSON('/api/events?limit=200'); render(snapshot); successful++;
    const delay = performance.now() - started; latencies.push(delay); latencies = latencies.slice(-60);
    put('ping-value', `${delay.toFixed(0)} ms`); put('conn-status', 'Dashboard connected'); el('global-dot').className = 'status-dot';
  } catch (error) {
    put('conn-status', `Disconnected (${error.message})`); el('global-dot').className = 'status-dot error';
    put('data-mode', 'UNAVAILABLE'); put('alert-container', 'Live feed unavailable. Displayed readings may be old.');
  }
  put('uptime-percent', `${(successful / polls * 100).toFixed(1)}%`);
  // Completion-based scheduling prevents overlapping polls under load.
  setTimeout(poll, 3000);
}
el('refresh-analysis').addEventListener('click', analysis);
window.addEventListener('resize', drawAll);
setInterval(() => put('clock', new Date().toLocaleTimeString()), 1000);
setInterval(analysis, 15000);
analysis(); poll();
