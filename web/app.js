let gDevices = [];
let gSearchQuery = '';
let gPollTimer = null;

// 现代化轻量 Toast 提示
function toast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = (type === 'success' ? '✅ ' : '⚠️ ') + msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(10px)';
    el.style.transition = 'all 0.25s ease';
    setTimeout(() => el.remove(), 250);
  }, 3200);
}

// 统一 API 调用（带乐观按钮加载态，绝不卡死界面）
function callApi(url, btnEl = null) {
  if (btnEl) btnEl.classList.add('loading');
  fetch(url)
    .then(r => r.json())
    .then(data => {
      if (btnEl) btnEl.classList.remove('loading');
      if (data.code === 0) {
        toast(data.message || '操作成功！', 'success');
      } else {
        toast(data.message || '执行失败', 'error');
      }
      refreshStatus(true);
    })
    .catch(err => {
      if (btnEl) btnEl.classList.remove('loading');
      toast('网络异常: ' + err, 'error');
    });
}

function handleSearch() {
  gSearchQuery = document.getElementById('searchInput').value.trim().toLowerCase();
  applyFiltersAndRender();
}

function getDeviceIcon(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('phone') || n.includes('xiaomi') || n.includes('iphone') || n.includes('hbn') || n.includes('al80') || n.includes('huawei')) return '📱';
  if (n.includes('laptop') || n.includes('asus') || n.includes('thinkpad') || n.includes('macbook')) return '💻';
  if (n.includes('desktop') || n.includes('pc') || n.includes('workstation')) return '🖥️';
  return '🌐';
}

function adjustPeriod(safeMac, delta) {
  const el = document.getElementById('period_' + safeMac);
  if (!el) return;
  let val = parseInt(el.value) || 30;
  val = Math.max(5, Math.min(300, val + delta));
  el.value = val;
}

function setQuickPeriod(safeMac, val) {
  const el = document.getElementById('period_' + safeMac);
  if (el) el.value = val;
}

function toggleFluctuate(mac, safeMac, isCurrentlyActive) {
  if (isCurrentlyActive) {
    callApi('/api/device/stop_fluctuate?mac=' + encodeURIComponent(mac));
  } else {
    const el = document.getElementById('period_' + safeMac);
    const period = el ? (parseInt(el.value) || 30) : 30;
    callApi('/api/device/fluctuate?mac=' + encodeURIComponent(mac) + '&period=' + period);
  }
}

// 核心：无感零卡顿 DOM 增量刷新引擎（保留输入框焦点与值，杜绝 innerHTML 粗暴刷白）
function applyFiltersAndRender() {
  const container = document.getElementById('deviceGrid');
  const filtered = gDevices.filter(dev => {
    if (!gSearchQuery) return true;
    const hay = ((dev.name || '') + ' ' + (dev.ip || '') + ' ' + (dev.mac || '')).toLowerCase();
    return hay.includes(gSearchQuery);
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 40px; color:#64748b;">未找到匹配的设备</div>';
    return;
  }

  // 移除已经被过滤掉的卡片
  const currentSafeMacs = new Set(filtered.map(d => d.mac.replace(/[^a-zA-Z0-9]/g, '_')));
  Array.from(container.children).forEach(child => {
    if (child.id && child.id.startsWith('card_')) {
      const sm = child.id.replace('card_', '');
      if (!currentSafeMacs.has(sm)) child.remove();
    }
  });

  filtered.forEach(dev => {
    const safeMac = dev.mac.replace(/[^a-zA-Z0-9]/g, '_');
    let card = document.getElementById('card_' + safeMac);
    const isFluc = dev.fluctuating === true;
    const isExempt = dev.exempt_flag === 1;
    const flucInfo = dev.fluctuation_info || {};
    const up = parseFloat(dev.qos?.upmax || 0);
    const down = parseFloat(dev.qos?.downmax || 0);

    // 档位速度文本
    let speedText = '全速 (0 KB/s)';
    let speedPillClass = 'pill-free';
    if (isFluc) {
      speedText = `波动: ${flucInfo.current_speed === 0 ? '全速' : flucInfo.current_speed + ' KB/s'}`;
      speedPillClass = 'pill-fluc';
    } else if (up > 0 || down > 0) {
      speedText = `限速: ${down} KB/s`;
      speedPillClass = 'pill-limit';
    }

    const isWhitelisted = dev.is_whitelisted === true;
    let flagPillHtml = '';
    if (isWhitelisted) {
      flagPillHtml = '<span class="pill pill-whitelist">🛡️ 永久白名单 (免限)</span>';
    } else if (isExempt) {
      flagPillHtml = '<span class="pill pill-exempt">🟢 已放行 (巡检跳过)</span>';
    } else {
      flagPillHtml = '<span class="pill pill-ctrl">⚪ 受控中 (参与管控)</span>';
    }

    if (!card) {
      // 首次创建新卡片
      card = document.createElement('div');
      card.id = 'card_' + safeMac;
      card.className = 'device-card' + (isFluc ? ' is-fluctuating' : '');

      card.innerHTML = `
        <div class="dev-head">
          <div class="dev-info-left">
            <div class="dev-avatar">${getDeviceIcon(dev.name)}</div>
            <div class="dev-titles">
              <div class="dev-name">${dev.name || '未知设备'}</div>
              <div class="dev-meta">${dev.ip || '-'} · ${dev.mac}</div>
            </div>
          </div>
        </div>

        <div class="badges-wrap" id="badges_${safeMac}">
          ${flagPillHtml}
          <span class="pill ${speedPillClass}" id="speedPill_${safeMac}">
            ${speedText}
          </span>
        </div>

        <div id="vizContainer_${safeMac}"></div>

        <div class="btn-group-2">
          <button class="btn-sub-action btn-exempt-opt" onclick="callApi('/api/device/exempt?mac=${encodeURIComponent(dev.mac)}', this)">
            🟢 手动放行
          </button>
          ${isWhitelisted 
            ? '<button class="btn-sub-action" style="opacity:0.5;cursor:not-allowed;" title="白名单设备受全局保护，不可限速" disabled>🛡️ 白名单保护</button>'
            : `<button class="btn-sub-action btn-limit-opt" onclick="callApi('/api/device/limit?mac=${encodeURIComponent(dev.mac)}', this)">🐢 手动限速</button>`
          }
        </div>

        <div class="fluc-console">
          <div class="fluc-console-top">
            <div class="stepper-wrap">
              <button class="stepper-btn" onclick="adjustPeriod('${safeMac}', -5)">−</button>
              <input type="number" id="period_${safeMac}" class="stepper-val" value="${flucInfo.period || 30}" min="5" max="300">
              <span class="stepper-unit">s</span>
              <button class="stepper-btn" onclick="adjustPeriod('${safeMac}', 5)">+</button>
            </div>
            <div class="quick-pills">
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 15)">15s</span>
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 30)">30s</span>
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 60)">60s</span>
            </div>
          </div>
          <button id="flucBtn_${safeMac}" class="btn-fluc-main ${isFluc ? 'btn-fluc-stop' : 'btn-fluc-start'}" onclick="toggleFluctuate('${dev.mac}', '${safeMac}', ${isFluc})">
            ${isFluc ? '🛑 停止波动 (即刻全速)' : '🌊 开启网络波动模拟'}
          </button>
        </div>
      `;
      container.appendChild(card);
    } else {
      // 增量热更新卡片样式和数值（无缝平滑，不闪烁）
      card.className = 'device-card' + (isFluc ? ' is-fluctuating' : '');
      const badgesEl = document.getElementById('badges_' + safeMac);
      if (badgesEl) {
        badgesEl.innerHTML = `
          ${flagPillHtml}
          <span class="pill ${speedPillClass}">
            ${speedText}
          </span>
        `;
      }

      // 更新主按钮
      const flucBtn = document.getElementById('flucBtn_' + safeMac);
      if (flucBtn) {
        flucBtn.className = 'btn-fluc-main ' + (isFluc ? 'btn-fluc-stop' : 'btn-fluc-start');
        flucBtn.innerHTML = isFluc ? '🛑 停止波动 (即刻全速)' : '🌊 开启网络波动模拟';
        flucBtn.onclick = () => toggleFluctuate(dev.mac, safeMac, isFluc);
      }
    }

    // 动态渲染可视化声波阶梯条
    const vizBox = document.getElementById('vizContainer_' + safeMac);
    if (vizBox) {
      if (isFluc) {
        const curStep = flucInfo.current_step || 0;
        const stages = flucInfo.stages || [13, 50, 200, 800, 0];
        const stepLabels = ['13K', '50K', '200K', '800K', '全速'];
        let stepsHtml = '';
        stages.forEach((stg, sIdx) => {
          const isCur = (sIdx === curStep);
          stepsHtml += `<span class="pipe-step ${isCur ? 'current' : ''}">${stepLabels[sIdx] || (stg + 'K')}</span>`;
        });

        vizBox.innerHTML = `
          <div class="fluc-viz-box">
            <div class="fluc-viz-top">
              <span style="font-size:11px;font-weight:700;color:#6d28d9;">🌊 实时波动阶梯 (周期 ${flucInfo.period}s)</span>
              <div class="eq-bars">
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
              </div>
            </div>
            <div class="stages-pipeline">
              ${stepsHtml}
            </div>
          </div>
        `;
      } else {
        vizBox.innerHTML = '';
      }
    }
  });
}

function updateHUD(list) {
  let exemptCount = 0;
  let limitedCount = 0;
  let flucCount = 0;

  list.forEach(d => {
    if (d.exempt_flag === 1) exemptCount++;
    const isFluc = d.fluctuating === true;
    if (isFluc) flucCount++;
    const up = parseFloat(d.qos?.upmax || 0);
    const down = parseFloat(d.qos?.downmax || 0);
    if (!isFluc && (up > 0 || down > 0)) limitedCount++;
  });

  document.getElementById('hudTotal').textContent = list.length;
  document.getElementById('hudExempt').textContent = exemptCount;
  document.getElementById('hudLimited').textContent = limitedCount;
  document.getElementById('hudFluc').textContent = flucCount;

  const flucCard = document.getElementById('hudFlucCard');
  if (flucCount > 0) flucCard.classList.add('active-fluc');
  else flucCard.classList.remove('active-fluc');
}

function refreshStatus(force = false) {
  fetch('/api/status' + (force ? '?refresh=1' : ''))
    .then(r => r.json())
    .then(data => {
      if (!data || !data.list) return;
      gDevices = data.list;
      updateHUD(gDevices);
      applyFiltersAndRender();

      // 智能自适应轮询：有波动任务时每 2.5 秒无感同步，无波动时每 8 秒心跳轮询
      const anyFluc = gDevices.some(d => d.fluctuating);
      if (gPollTimer) clearTimeout(gPollTimer);
      gPollTimer = setTimeout(() => refreshStatus(false), anyFluc ? 2500 : 8000);
    })
    .catch(() => {
      document.getElementById('sysStatusText').textContent = '连接重试中...';
      if (gPollTimer) clearTimeout(gPollTimer);
      gPollTimer = setTimeout(() => refreshStatus(false), 5000);
    });
}

refreshStatus(true);
