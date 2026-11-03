// iFoxy Desktop Client Frontend Engine (PFP - Pixel & Protocol Architecture)
(function() {
  // App State
  let vpnState = 'disconnected'; // 'disconnected' | 'connecting' | 'connected'
  let isAuthenticated = false;
  let userEmail = '';
  let selectedServer = {
    countryCode: 'REC',
    countryName: 'Recommended',
    cityCode: 'AUTO',
    cityName: 'Fastest Edge Node',
    latency: 'Auto'
  };
  let serverList = [];
  let statusPollInterval = null;
  let opInFlight = false; // F3: a connect/disconnect invoke is in flight
  let connectedSince = null; // D9: client-side session start timestamp
  let serverListError = false; // F13: last fetch failed -> show a retry row

  // Screen Elements
  const screenSplash = document.getElementById('screen-splash');
  const screenLogin = document.getElementById('screen-login');
  const screenHome = document.getElementById('screen-home');

  // Home Screen Elements
  const powerButton = document.getElementById('power-button');
  const statusText = document.getElementById('status-text');
  const statusHint = document.getElementById('status-hint');
  const speedDown = document.getElementById('speed-down');
  const speedUp = document.getElementById('speed-up');
  const currentLocationTitle = document.getElementById('current-location-title');
  const currentLocationSub = document.getElementById('current-location-sub');
  const currentLatency = document.getElementById('current-latency');
  const quotaText = document.getElementById('quota-text');
  const quotaBar = document.getElementById('quota-bar');

  // Drawer & Modal Elements
  const modalServers = document.getElementById('modal-servers');
  const modalSettings = document.getElementById('modal-settings');
  const modalLogs = document.getElementById('modal-logs');

  const btnSelectLocation = document.getElementById('btn-select-location');
  const btnOpenSettings = document.getElementById('btn-open-settings');
  const btnOpenLogs = document.getElementById('btn-open-logs');

  const btnCloseServers = document.getElementById('btn-close-servers');
  const btnCloseSettings = document.getElementById('btn-close-settings');
  const btnCloseLogs = document.getElementById('btn-close-logs');
  const btnThemeToggle = document.getElementById('btn-theme-toggle');

  // Login Screen Elements
  const loginStepCredentials = document.getElementById('login-step-credentials');
  const loginStep2fa = document.getElementById('login-step-2fa');
  const loginEmail = document.getElementById('login-email');
  const loginPassword = document.getElementById('login-password');
  const loginCode = document.getElementById('login-code');
  const loginError = document.getElementById('login-error');
  const twofaError = document.getElementById('twofa-error');
  const btnSubmitLogin = document.getElementById('btn-submit-login');
  const btnSubmit2fa = document.getElementById('btn-submit-2fa');
  const btnBackToCredentials = document.getElementById('btn-back-to-credentials');

  // Settings & Account Elements
  const settingsUserEmail = document.getElementById('settings-user-email');
  const settingTunnelMode = document.getElementById('setting-tunnel-mode');
  const btnLogout = document.getElementById('btn-logout');

  // Server List Elements
  const serverSearch = document.getElementById('server-search');
  const serverListContainer = document.getElementById('server-list-container');
  const logsContainer = document.getElementById('logs-container');

  // Session / proxy / settings additions (fix wave)
  const sessionRow = document.getElementById('session-row');
  const sessionBytes = document.getElementById('session-bytes');
  const sessionDuration = document.getElementById('session-duration');
  const proxyRow = document.getElementById('proxy-row');
  const proxyEndpoint = document.getElementById('proxy-endpoint');
  const subscriptionBadge = document.getElementById('settings-subscription-badge');
  const btnCopyLogs = document.getElementById('btn-copy-logs');
  const btnClearLogs = document.getElementById('btn-clear-logs');

  // ==================== NAVIGATION ====================
  function showScreen(screenId) {
    [screenSplash, screenLogin, screenHome].forEach(s => {
      if (s) s.classList.remove('active');
    });
    const target = document.getElementById(screenId);
    if (target) {
      target.classList.add('active');
    }
  }

  // Drawer stack + per-drawer hide timers (F17: reopening within the
  // 300 ms close window must cancel the pending hide) and openers for
  // focus restore (F4).
  const openDrawers = [];
  const drawerHideTimers = new Map();
  const drawerOpeners = new Map();

  function openDrawer(drawer, opener) {
    if (!drawer) return;
    clearTimeout(drawerHideTimers.get(drawer));
    drawer.style.display = 'flex';
    setTimeout(() => drawer.classList.add('active'), 10);
    if (!openDrawers.includes(drawer)) openDrawers.push(drawer);
    drawerOpeners.set(drawer, opener || document.activeElement);
    const closeBtn = drawer.querySelector('.drawer-header .icon-btn');
    if (closeBtn) setTimeout(() => closeBtn.focus(), 60);
  }

  function closeDrawer(drawer) {
    if (!drawer) return;
    drawer.classList.remove('active');
    const idx = openDrawers.indexOf(drawer);
    if (idx >= 0) openDrawers.splice(idx, 1);
    clearTimeout(drawerHideTimers.get(drawer));
    drawerHideTimers.set(drawer, setTimeout(() => { drawer.style.display = 'none'; }, 300));
    const opener = drawerOpeners.get(drawer);
    drawerOpeners.delete(drawer);
    if (opener && opener.focus) opener.focus();
  }

  // Backdrop click closes; Escape closes the topmost open drawer (F4).
  [modalServers, modalSettings, modalLogs].forEach(d => {
    if (d) d.addEventListener('click', (e) => { if (e.target === d) closeDrawer(d); });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && openDrawers.length > 0) {
      closeDrawer(openDrawers[openDrawers.length - 1]);
    }
  });

  // Keyboard activation helper for the div-based controls (F4).
  function activateOnKey(el, handler) {
    if (!el) return;
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler(e);
      }
    });
  }

  // ==================== LOGGING ====================
  function log(msg) {
    if (!logsContainer) return;
    const timestamp = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.textContent = `[${timestamp}] ${msg}`;
    logsContainer.appendChild(entry);
    // Bounded log buffer (H10): max 500 lines to prevent unbounded memory growth
    while (logsContainer.childNodes.length > 500) {
      logsContainer.removeChild(logsContainer.firstChild);
    }
    logsContainer.scrollTop = logsContainer.scrollHeight;
  }

  // Backend log lines live in a dedicated wrapper inserted as the first
  // child of the terminal, so JS log() lines always append after them
  // (F1/D1). Refreshed from the bridge's get_logs buffer on drawer open.
  let backendLogsEl = null;
  function ensureBackendLogsEl() {
    if (!logsContainer) return null;
    if (!backendLogsEl || !logsContainer.contains(backendLogsEl)) {
      backendLogsEl = document.createElement('div');
      backendLogsEl.className = 'backend-logs';
      logsContainer.insertBefore(backendLogsEl, logsContainer.firstChild);
    }
    return backendLogsEl;
  }

  async function refreshBackendLogs() {
    if (!logsContainer) return;
    try {
      const res = await invoke('get_logs');
      if (res && Array.isArray(res.logs)) {
        const wrap = ensureBackendLogsEl();
        if (!wrap) return;
        while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
        res.logs.forEach(line => {
          const el = document.createElement('div');
          el.textContent = line;
          wrap.appendChild(el);
        });
        logsContainer.scrollTop = logsContainer.scrollHeight;
      }
    } catch (_) {}
  }

  // ==================== BACKEND IPC ====================
  async function invoke(cmd, args = {}) {
    try {
      const token = window.__IFOXY_TOKEN__ || '';
      const headers = { 'Content-Type': 'application/json' };
      if (token) {
        headers['X-iFoxy-Token'] = token;
      }
      const res = await fetch(`/api/${cmd}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(args)
      });
      return await res.json();
    } catch (e) {
      console.warn(`IPC call failed for ${cmd}:`, e);
      return { success: false, error: e.toString() };
    }
  }

  // ==================== AUTHENTICATION ====================
  // Match the backend's email-masking convention in UI log lines (F9).
  function maskEmail(email) {
    const at = (email || '').indexOf('@');
    if (at <= 0) return '***';
    return `${email[0]}***@${email.slice(at + 1)}`;
  }

  async function checkAuthState() {
    try {
      const auth = await invoke('get_auth_state');
      // F29: invoke() only reports success:false when the local control
      // service itself could not be reached (a live backend answers
      // get_auth_state without a success field). Distinguish a dead
      // backend from simply being signed out.
      if (auth && auth.success === false) {
        isAuthenticated = false;
        userEmail = '';
        showScreen('screen-login');
        showError(loginError, "Couldn't reach the local app service — if this persists, restart iFoxy.");
        log('Local app service unreachable during auth check.');
        return;
      }
      if (auth && auth.is_authenticated && auth.email) {
        isAuthenticated = true;
        userEmail = auth.email;
        updateAccountDisplay();
        showScreen('screen-home');
        log(`Resumed session for ${maskEmail(userEmail)}`);
        // F13: session-resume path must fetch the server list too.
        fetchServerList();
      } else {
        isAuthenticated = false;
        userEmail = '';
        showScreen('screen-login');
        log('No stored session. Please sign in with your Firefox Account.');
      }
    } catch (e) {
      isAuthenticated = false;
      showScreen('screen-login');
    }
  }

  async function updateAccountDisplay() {
    if (settingsUserEmail) {
      settingsUserEmail.textContent = userEmail || '';
    }
    try {
      const ent = await invoke('get_entitlement');
      if (ent && ent.success) {
        // F7/G2: drive the Subscription badge from the real entitlement.
        if (subscriptionBadge) {
          subscriptionBadge.textContent = ent.subscribed ? 'Mozilla VPN subscription' : 'Free 50 GB Monthly';
        }
        if (ent.quota_remaining !== undefined && ent.quota_remaining !== null) {
          const gbRem = (ent.quota_remaining / (1024 * 1024 * 1024)).toFixed(1);
          if (quotaText) quotaText.textContent = `${gbRem} GB remaining`;
          if (quotaBar) {
            if (ent.max_bytes) {
              const pct = Math.min(100, Math.max(0, (ent.quota_remaining / ent.max_bytes) * 100));
              quotaBar.style.width = `${pct}%`;
            } else {
              // F24: no known maximum -> no stale bar width.
              quotaBar.style.width = '0%';
            }
          }
          return;
        }
      }
    } catch (_) {}
    // Never show an invented allowance: if the real quota is unknown, say so.
    if (quotaText) {
      quotaText.textContent = 'Quota unavailable';
    }
    if (quotaBar) {
      quotaBar.style.width = '0%';
    }
  }

  // Submit Login Credentials
  btnSubmitLogin.addEventListener('click', async () => {
    const email = loginEmail.value.trim();
    const password = loginPassword.value;

    if (!email || !password) {
      showError(loginError, 'Please enter both email and password');
      return;
    }

    hideError(loginError);
    setButtonLoading(btnSubmitLogin, true, 'Authenticating...');

    try {
      log(`Authenticating with Firefox Accounts (${maskEmail(email)})...`);
      const res = await invoke('login', { email, password });
      
      if (res && res.success) {
        loginPassword.value = '';
        if (res.needs_2fa) {
          log('Two-factor verification code required. Check your email inbox.');
          loginStepCredentials.style.display = 'none';
          loginStep2fa.style.display = 'block';
          loginCode.value = '';
          loginCode.focus();
        } else {
          finishLogin(email);
        }
      } else {
        const msg = (res && res.error) ? res.error : 'Incorrect email or password';
        showError(loginError, msg);
        log(`Authentication error: ${msg}`);
      }
    } catch (e) {
      showError(loginError, e.toString());
    } finally {
      setButtonLoading(btnSubmitLogin, false, 'Continue');
    }
  });

  // Submit 2FA Code
  btnSubmit2fa.addEventListener('click', async () => {
    const code = loginCode.value.trim();
    if (!code || code.length < 6) {
      showError(twofaError, 'Please enter the 6-digit confirmation code');
      return;
    }

    hideError(twofaError);
    setButtonLoading(btnSubmit2fa, true, 'Verifying...');

    try {
      // Never log the code itself (wave-3 review, M-14).
      log('Verifying 2FA code...');
      const res = await invoke('verify_2fa', { code });

      if (res && res.success) {
        finishLogin(loginEmail.value.trim() || res.email);
      } else {
        const msg = (res && res.error) ? res.error : 'Invalid confirmation code';
        if (msg.toLowerCase().includes('sign in again')) {
          // F19: the bridge dropped the pending session (attempt cap or
          // TTL) — staying on the 2FA step can never succeed, so return
          // to the credentials step and surface the message there.
          loginStep2fa.style.display = 'none';
          loginStepCredentials.style.display = 'block';
          hideError(twofaError);
          showError(loginError, msg);
          log(`2FA session ended: ${msg}`);
        } else {
          showError(twofaError, msg);
          log(`2FA error: ${msg}`);
        }
      }
    } catch (e) {
      showError(twofaError, e.toString());
    } finally {
      setButtonLoading(btnSubmit2fa, false, 'Verify & Sign In');
    }
  });

  // Allow pressing Enter in the login fields to submit, like clicking the button
  function onEnterSubmit(input, button) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.isComposing && !button.disabled) {
        e.preventDefault();
        button.click();
      }
    });
  }
  onEnterSubmit(loginEmail, btnSubmitLogin);
  onEnterSubmit(loginPassword, btnSubmitLogin);
  onEnterSubmit(loginCode, btnSubmit2fa);

  // F19: keep the confirmation code numeric-only as the user types.
  loginCode.addEventListener('input', () => {
    const digits = loginCode.value.replace(/\D/g, '');
    if (digits !== loginCode.value) loginCode.value = digits;
  });

  btnBackToCredentials.addEventListener('click', () => {
    loginStep2fa.style.display = 'none';
    loginStepCredentials.style.display = 'block';
    hideError(twofaError);
  });

  function finishLogin(email) {
    isAuthenticated = true;
    userEmail = email;
    updateAccountDisplay();
    showScreen('screen-home');
    log(`Successfully signed in as ${maskEmail(email)}.`);
    // Fetch servers in background
    fetchServerList();
  }

  // Sign Out
  btnLogout.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to sign out of your Firefox Account?')) {
      return;
    }
    log('Signing out...');
    btnLogout.disabled = true;
    try {
      // F11: only clear local state when the bridge confirms sign-out;
      // on failure the stored session may still be alive server-side.
      const res = await invoke('logout');
      if (!res || !res.success) {
        const msg = (res && res.error) ? res.error : 'Sign out failed';
        log(`Sign out failed: ${msg}`);
        return;
      }
      isAuthenticated = false;
      userEmail = '';
      setVpnState('disconnected');
      closeDrawer(modalSettings);

      // Reset inputs
      loginEmail.value = '';
      loginPassword.value = '';
      loginCode.value = '';
      loginStep2fa.style.display = 'none';
      loginStepCredentials.style.display = 'block';
      hideError(loginError);
      hideError(twofaError);

      showScreen('screen-login');
      log('Signed out cleanly.');
    } finally {
      btnLogout.disabled = false;
    }
  });

  function showError(el, msg) {
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
  }

  function hideError(el) {
    if (!el) return;
    el.style.display = 'none';
    el.textContent = '';
  }

  function setButtonLoading(btn, isLoading, text) {
    if (!btn) return;
    btn.disabled = isLoading;
    const txt = btn.querySelector('.btn-text');
    const sp = btn.querySelector('.btn-spinner');
    if (txt) txt.textContent = text;
    if (sp) sp.style.display = isLoading ? 'inline-block' : 'none';
  }

  // ==================== VPN CONNECTION ====================
  function zeroSpeedDisplays() {
    speedDown.textContent = '0.0 KB/s';
    speedUp.textContent = '0.0 KB/s';
  }

  function setVpnState(newState, extra) {
    vpnState = newState;
    const ringClass = (newState === 'reconnecting') ? 'connecting' : (newState === 'disconnecting' || newState === 'failed' ? 'disconnected' : newState);
    powerButton.className = 'power-button-wrapper state-' + ringClass;

    if (newState === 'connected') {
      statusText.textContent = 'Connected';
      statusText.style.color = 'var(--state-connected)';
      statusHint.textContent = `Secured via ${selectedServer.countryName}`;
    } else if (newState === 'connecting') {
      statusText.textContent = 'Connecting…';
      statusText.style.color = 'var(--state-connecting)';
      statusHint.textContent = 'Tap to cancel';
      zeroSpeedDisplays();
    } else if (newState === 'reconnecting') {
      statusText.textContent = 'Reconnecting…';
      statusText.style.color = '#ff9431';
      statusHint.textContent = extra || 'Re-establishing tunnel';
      zeroSpeedDisplays();
    } else if (newState === 'disconnecting') {
      statusText.textContent = 'Disconnecting…';
      statusText.style.color = 'var(--text-secondary)';
      statusHint.textContent = 'Restoring network';
      zeroSpeedDisplays();
    } else if (newState === 'failed') {
      statusText.textContent = 'Connection Failed';
      statusText.style.color = '#ff4d4d';
      statusHint.textContent = extra || 'Tap to retry';
      zeroSpeedDisplays();
    } else {
      statusText.textContent = 'Disconnected';
      statusText.style.color = 'var(--text-primary)';
      statusHint.textContent = 'Tap to connect';
      zeroSpeedDisplays();
    }
  }

  let lastBytesDown = 0;
  let lastBytesUp = 0;
  let lastPollTime = Date.now();

  function formatBytesPerSec(bytes) {
    if (bytes >= 1048576) {
      return (bytes / 1048576).toFixed(1) + ' MB/s';
    }
    return (bytes / 1024).toFixed(1) + ' KB/s';
  }

  // F12: speeds are computed from the single status poll's payload —
  // there is no separate speed interval anymore.
  let speedTracking = false;
  function updateSpeeds(status) {
    const now = Date.now();
    const dt = Math.max(1, (now - lastPollTime) / 1000);
    lastPollTime = now;
    if (status.state === 'connected' &&
        status.bytes_received !== undefined && status.bytes_sent !== undefined) {
      if (speedTracking) {
        const rxRate = Math.max(0, (status.bytes_received - lastBytesDown) / dt);
        const txRate = Math.max(0, (status.bytes_sent - lastBytesUp) / dt);
        speedDown.textContent = formatBytesPerSec(rxRate);
        speedUp.textContent = formatBytesPerSec(txRate);
      }
      lastBytesDown = status.bytes_received;
      lastBytesUp = status.bytes_sent;
      speedTracking = true;
    } else {
      speedTracking = false;
      zeroSpeedDisplays();
    }
  }

  function formatBytes(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1024).toFixed(1) + ' KB';
  }

  function formatDuration(totalSecs) {
    const h = Math.floor(totalSecs / 3600);
    const m = Math.floor((totalSecs % 3600) / 60);
    const s = totalSecs % 60;
    const mm = String(m).padStart(2, '0');
    const ss = String(s).padStart(2, '0');
    return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
  }

  // D9: session totals + duration from the same polled status payload.
  function updateSessionRow(status) {
    if (!sessionRow) return;
    if (status.state === 'connected') {
      if (!connectedSince) connectedSince = Date.now();
      sessionRow.style.display = 'flex';
      if (sessionBytes) {
        sessionBytes.textContent = `\u2193 ${formatBytes(status.bytes_received || 0)} \u00b7 \u2191 ${formatBytes(status.bytes_sent || 0)}`;
      }
      if (sessionDuration) {
        sessionDuration.textContent = formatDuration(Math.floor((Date.now() - connectedSince) / 1000));
      }
    } else {
      connectedSince = null;
      sessionRow.style.display = 'none';
    }
  }

  // D2: surface the local proxy endpoint while connected in proxy_only
  // mode. The port is the engine constant DEFAULT_LOCAL_PROXY_PORT
  // (src/vpn/local_proxy.rs:79).
  const LOCAL_PROXY_ENDPOINT = '127.0.0.1:10800';
  function updateProxyRow(status) {
    if (!proxyRow) return;
    const mode = status.mode || tunnelMode();
    if (status.state === 'connected' && mode === 'proxy_only') {
      proxyRow.style.display = 'flex';
    } else {
      proxyRow.style.display = 'none';
    }
  }

  // Real backend state synchronization loop (R-12, H9, H2)
  async function pollVpnStatus() {
    try {
      const status = await invoke('get_vpn_status');
      if (!status || !status.state) return;

      // F12: this single poll feeds speeds, the session row and the
      // proxy-endpoint row as well as the state machine below.
      updateSpeeds(status);
      updateSessionRow(status);
      updateProxyRow(status);

      // F3: while a connect/disconnect invoke is in flight, never let
      // the poll stomp the optimistic state the click handler set.
      if (opInFlight) return;

      if (status.state === 'connected') {
        if (vpnState !== 'connected') {
          if (status.current_country) {
            selectedServer.countryName = status.current_country;
            if (status.current_city) selectedServer.cityName = status.current_city;
            currentLocationTitle.textContent = status.current_country;
            currentLocationSub.textContent = status.current_city || '';
          }
          log(`Tunnel verified active by backend in ${status.mode || 'proxy_only'} mode`);
          setVpnState('connected');
        }
      } else if (status.state === 'connecting') {
        if (vpnState !== 'connecting') {
          setVpnState('connecting');
        }
      } else if (status.state === 'reconnecting') {
        if (vpnState !== 'reconnecting') {
          log(`Tunnel reconnecting (attempt ${status.attempt || 1})`);
          setVpnState('reconnecting', `Attempt ${status.attempt || 1}`);
        }
      } else if (status.state === 'disconnecting') {
        if (vpnState !== 'disconnecting') {
          setVpnState('disconnecting');
        }
      } else if (status.state === 'failed') {
        if (vpnState !== 'failed') {
          log(`Tunnel failed: ${status.error || 'Unknown error'}`);
          setVpnState('failed', status.error);
        }
      } else if (status.state === 'disconnected') {
        if (vpnState !== 'disconnected') {
          setVpnState('disconnected');
        }
      }
    } catch (_) {}
  }

  function tunnelMode() {
    return settingTunnelMode ? settingTunnelMode.value : 'proxy_only';
  }

  // Power Button Action with real cancellation.
  // F3: opInFlight guards the whole operation — extra clicks are
  // ignored and pollVpnStatus will not overwrite the optimistic state
  // until the invoke settles (the guard always resets via finally).
  async function onPowerButton() {
    if (!isAuthenticated) {
      showScreen('screen-login');
      return;
    }
    if (opInFlight) return;

    if (vpnState === 'disconnected' || vpnState === 'failed') {
      opInFlight = true;
      const mode = tunnelMode();
      setVpnState('connecting');
      try {
        log(`Initiating tunnel to ${selectedServer.countryName} (${selectedServer.cityName}) in ${mode} mode...`);
        const res = await invoke('connect_vpn', {
          country_code: selectedServer.countryCode,
          city_code: selectedServer.cityCode,
          mode: mode
        });

        if (res && res.success) {
          log('Connection request accepted by backend. Awaiting tunnel activation...');
          // G5/F25: show the bridge's probed latency for the chosen node.
          if (res.latency_ms !== undefined && res.latency_ms !== null) {
            currentLatency.textContent = `${res.latency_ms} ms`;
          }
        } else {
          const err = (res && res.error) ? res.error : 'Connection initiation failed';
          log(`Failed to initiate connect: ${err}`);
          setVpnState('failed', err);
        }
      } catch (err) {
        log(`Connection exception: ${err}`);
        setVpnState('failed', err.toString());
      } finally {
        opInFlight = false;
      }
    } else if (vpnState === 'connecting' || vpnState === 'reconnecting' || vpnState === 'connected') {
      opInFlight = true;
      try {
        log(vpnState === 'connected' ? 'Disconnecting VPN...' : 'User cancelled connection in progress.');
        setVpnState('disconnecting');
        await invoke('disconnect_vpn');
        setVpnState('disconnected');
      } finally {
        opInFlight = false;
      }
    }
    // 'disconnecting': a disconnect is already running — ignore clicks.
  }
  powerButton.addEventListener('click', onPowerButton);
  activateOnKey(powerButton, onPowerButton);

  // ==================== SERVER LIST ====================
  // D6/F13: there is deliberately NO fabricated fallback list — the
  // engine refuses to invent hosts, so the UI must not offer invented
  // locations either. A failed fetch shows an explicit retry row.
  const RECOMMENDED_SERVER = { countryCode: 'REC', countryName: 'Recommended', cityCode: 'AUTO', cityName: 'Fastest Edge Node', latency: 'Auto' };

  async function fetchServerList() {
    serverListError = false;
    try {
      const res = await invoke('fetch_server_list');
      if (res && res.success && res.countries && res.countries.length > 0) {
        serverList = [RECOMMENDED_SERVER]; // Recommended first
        res.countries.forEach(c => {
          c.cities.forEach(city => {
            serverList.push({
              countryCode: c.code,
              countryName: c.name,
              cityCode: city.code,
              cityName: city.name,
              latency: city.latency_ms ? `${city.latency_ms} ms` : '-- ms'
            });
          });
        });
      } else {
        serverList = [];
        serverListError = true;
      }
    } catch (e) {
      serverList = [];
      serverListError = true;
    }
    renderServers(serverList);
  }

  function selectServer(item) {
    selectedServer = item;
    currentLocationTitle.textContent = item.countryName;
    currentLocationSub.textContent = item.cityName;
    currentLatency.textContent = item.latency;
    closeDrawer(modalServers);
    log(`Selected Server: ${item.countryName} - ${item.cityName}`);
  }

  function renderServers(list) {
    if (!serverListContainer) return;
    while (serverListContainer.firstChild) {
      serverListContainer.removeChild(serverListContainer.firstChild);
    }
    if (list.length === 0) {
      if (serverListError) {
        const wrap = document.createElement('div');
        wrap.className = 'server-error';
        const msg = document.createElement('div');
        msg.textContent = "Couldn't load locations";
        const retry = document.createElement('button');
        retry.className = 'btn-mini';
        retry.textContent = 'Retry';
        retry.addEventListener('click', () => fetchServerList());
        wrap.appendChild(msg);
        wrap.appendChild(retry);
        serverListContainer.appendChild(wrap);
      } else {
        const empty = document.createElement('div');
        empty.className = 'server-empty';
        empty.textContent = 'No locations match your search';
        serverListContainer.appendChild(empty);
      }
      return;
    }
    list.forEach(item => {
      const row = document.createElement('div');
      row.className = 'server-item';
      row.tabIndex = 0;
      // F16: mark the row that matches the current selection.
      if (item.countryCode === selectedServer.countryCode && item.cityCode === selectedServer.cityCode) {
        row.classList.add('selected');
      }

      const leftWrap = document.createElement('div');
      leftWrap.style.display = 'flex';
      leftWrap.style.alignItems = 'center';
      leftWrap.style.gap = '12px';

      const dot = document.createElement('div');
      dot.style.width = '10px';
      dot.style.height = '10px';
      dot.style.borderRadius = '50%';
      dot.style.background = '#00e676';
      dot.style.flexShrink = '0';

      const textWrap = document.createElement('div');
      const titleEl = document.createElement('div');
      titleEl.style.fontWeight = '600';
      titleEl.style.fontSize = '0.95rem';
      titleEl.textContent = item.countryName;

      const subEl = document.createElement('div');
      subEl.style.color = 'var(--text-secondary)';
      subEl.style.fontSize = '0.8rem';
      subEl.textContent = item.cityName;

      textWrap.appendChild(titleEl);
      textWrap.appendChild(subEl);
      leftWrap.appendChild(dot);
      leftWrap.appendChild(textWrap);

      const badge = document.createElement('div');
      badge.className = 'latency-badge';
      badge.textContent = item.latency;

      row.appendChild(leftWrap);
      row.appendChild(badge);

      row.addEventListener('click', () => selectServer(item));
      activateOnKey(row, () => selectServer(item));
      serverListContainer.appendChild(row);
    });
  }

  if (serverSearch) {
    let searchDebounce = null;
    serverSearch.addEventListener('input', (e) => {
      // F16: debounce re-renders while typing.
      clearTimeout(searchDebounce);
      const q = e.target.value.toLowerCase();
      searchDebounce = setTimeout(() => {
        const filtered = serverList.filter(s =>
          s.countryName.toLowerCase().includes(q) || s.cityName.toLowerCase().includes(q)
        );
        renderServers(filtered);
      }, 150);
    });
  }

  // Drawer event listeners
  function openServersDrawer() {
    if (serverList.length === 0) {
      fetchServerList();
    }
    openDrawer(modalServers, btnSelectLocation);
  }
  btnSelectLocation.addEventListener('click', openServersDrawer);
  activateOnKey(btnSelectLocation, openServersDrawer);
  btnCloseServers.addEventListener('click', () => closeDrawer(modalServers));

  btnOpenSettings.addEventListener('click', () => {
    updateAccountDisplay();
    openDrawer(modalSettings, btnOpenSettings);
  });
  btnCloseSettings.addEventListener('click', () => closeDrawer(modalSettings));

  btnOpenLogs.addEventListener('click', () => {
    openDrawer(modalLogs, btnOpenLogs);
    // F1/D1: (re)load the backend log lines every time the drawer opens.
    refreshBackendLogs();
  });
  btnCloseLogs.addEventListener('click', () => closeDrawer(modalLogs));

  // Logs drawer actions (F1): copy the full visible text, or clear the
  // visible list (the backend buffer itself is untouched).
  if (btnCopyLogs) {
    btnCopyLogs.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(logsContainer ? logsContainer.innerText : '');
      } catch (_) {}
      const orig = btnCopyLogs.textContent;
      btnCopyLogs.textContent = 'Copied';
      setTimeout(() => { btnCopyLogs.textContent = orig; }, 1200);
    });
  }
  if (btnClearLogs) {
    btnClearLogs.addEventListener('click', () => {
      if (!logsContainer) return;
      while (logsContainer.firstChild) logsContainer.removeChild(logsContainer.firstChild);
      backendLogsEl = null;
    });
  }

  // Local proxy endpoint row: click copies the endpoint (D2).
  function copyProxyEndpoint() {
    if (!proxyEndpoint) return;
    try { navigator.clipboard.writeText(LOCAL_PROXY_ENDPOINT); } catch (_) {}
    const orig = proxyEndpoint.textContent;
    proxyEndpoint.textContent = 'Copied!';
    setTimeout(() => { proxyEndpoint.textContent = orig; }, 1200);
  }
  if (proxyRow) {
    proxyRow.addEventListener('click', copyProxyEndpoint);
    activateOnKey(proxyRow, copyProxyEndpoint);
  }

  // ==================== PREFERENCES (F18/D4/D5) ====================
  function applyTheme(theme, save) {
    document.documentElement.setAttribute('data-theme', theme);
    if (save) {
      try { localStorage.setItem('ifoxy-theme', theme); } catch (_) {}
    }
    // F24/F18: the toggle advertises the theme it will switch TO.
    if (btnThemeToggle) {
      btnThemeToggle.title = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
    }
  }

  btnThemeToggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    applyTheme(currentTheme === 'light' ? 'dark' : 'light', true);
  });

  if (settingTunnelMode) {
    settingTunnelMode.addEventListener('change', () => {
      try { localStorage.setItem('ifoxy-tunnel-mode', settingTunnelMode.value); } catch (_) {}
      log(`Tunnel mode set to ${settingTunnelMode.value}.`);
      if (vpnState === 'connected' || vpnState === 'connecting' || vpnState === 'reconnecting') {
        statusHint.textContent = 'Tunnel mode applies on next connect';
      }
    });
  }

  function initPreferences() {
    let storedTheme = null;
    let storedMode = null;
    try {
      storedTheme = localStorage.getItem('ifoxy-theme');
      storedMode = localStorage.getItem('ifoxy-tunnel-mode');
    } catch (_) {}
    const initialTheme = storedTheme ||
      (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    applyTheme(initialTheme, false);
    if (storedMode && settingTunnelMode) {
      settingTunnelMode.value = storedMode;
    }
  }

  // ==================== INITIALIZATION ====================
  initPreferences();
  log('iFoxy Windows Desktop Engine Initialized');
  log('Native Subsystem: Active (No Terminal)');
  // F23: report the routing that matches the selected tunnel mode.
  log(tunnelMode() === 'full'
    ? 'Routing: Full System (Wintun L3 TUN) + WinINet Proxy'
    : 'Routing: Proxy Only (local proxy + system proxy settings)');

  // Start with Splash screen for 600ms, then check auth state
  setTimeout(() => {
    checkAuthState();
    statusPollInterval = setInterval(pollVpnStatus, 1000);
  }, 600);
})();
