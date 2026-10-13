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
  let speedInterval = null;
  let statusPollInterval = null;

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

  function openDrawer(drawer) {
    if (!drawer) return;
    drawer.style.display = 'flex';
    setTimeout(() => drawer.classList.add('active'), 10);
  }

  function closeDrawer(drawer) {
    if (!drawer) return;
    drawer.classList.remove('active');
    setTimeout(() => drawer.style.display = 'none', 300);
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

  // ==================== BACKEND IPC ====================
  async function invoke(cmd, args = {}) {
    try {
      const token = window.__IFOXY_TOKEN__ || document.querySelector('meta[name="ifoxy-api-token"]')?.getAttribute('content') || '';
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
  async function checkAuthState() {
    try {
      const auth = await invoke('get_auth_state');
      if (auth && auth.is_authenticated && auth.email) {
        isAuthenticated = true;
        userEmail = auth.email;
        updateAccountDisplay();
        showScreen('screen-home');
        log(`Resumed session for ${userEmail}`);
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
      if (ent && ent.success && ent.quota_remaining !== undefined && ent.quota_remaining !== null) {
        const gbRem = (ent.quota_remaining / (1024 * 1024 * 1024)).toFixed(1);
        if (quotaText) quotaText.textContent = `${gbRem} GB remaining`;
        if (quotaBar && ent.max_bytes) {
          const pct = Math.min(100, Math.max(0, (ent.quota_remaining / ent.max_bytes) * 100));
          quotaBar.style.width = `${pct}%`;
        }
        return;
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
      log(`Authenticating with Firefox Accounts (${email})...`);
      const res = await invoke('login', { email, password });
      
      if (res && res.success) {
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
      log(`Verifying 2FA code ${code}...`);
      const res = await invoke('verify_2fa', { code });

      if (res && res.success) {
        finishLogin(loginEmail.value.trim() || res.email);
      } else {
        const msg = (res && res.error) ? res.error : 'Invalid confirmation code';
        showError(twofaError, msg);
        log(`2FA error: ${msg}`);
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
    log(`Successfully signed in as ${email}.`);
    // Fetch servers in background
    fetchServerList();
  }

  // Sign Out
  btnLogout.addEventListener('click', async () => {
    if (confirm('Are you sure you want to sign out of your Firefox Account?')) {
      log('Signing out...');
      await invoke('logout');
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
  function setVpnState(newState, extra) {
    vpnState = newState;
    const ringClass = (newState === 'reconnecting') ? 'connecting' : (newState === 'disconnecting' || newState === 'failed' ? 'disconnected' : newState);
    powerButton.className = 'power-button-wrapper state-' + ringClass;

    if (newState === 'connected') {
      statusText.textContent = 'Connected';
      statusText.style.color = 'var(--state-connected)';
      statusHint.textContent = `Secured via ${selectedServer.countryName}`;
      startSpeedMeters();
    } else if (newState === 'connecting') {
      statusText.textContent = 'Connecting…';
      statusText.style.color = 'var(--state-connecting)';
      statusHint.textContent = 'Tap to cancel';
      stopSpeedMeters();
    } else if (newState === 'reconnecting') {
      statusText.textContent = 'Reconnecting…';
      statusText.style.color = '#ff9431';
      statusHint.textContent = extra || 'Re-establishing tunnel';
      stopSpeedMeters();
    } else if (newState === 'disconnecting') {
      statusText.textContent = 'Disconnecting…';
      statusText.style.color = 'var(--text-secondary)';
      statusHint.textContent = 'Restoring network';
      stopSpeedMeters();
    } else if (newState === 'failed') {
      statusText.textContent = 'Connection Failed';
      statusText.style.color = '#ff4d4d';
      statusHint.textContent = extra || 'Tap to retry';
      stopSpeedMeters();
    } else {
      statusText.textContent = 'Disconnected';
      statusText.style.color = 'var(--text-primary)';
      statusHint.textContent = 'Tap to connect';
      stopSpeedMeters();
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

  function startSpeedMeters() {
    if (speedInterval) clearInterval(speedInterval);
    lastPollTime = Date.now();
    speedInterval = setInterval(async () => {
      if (vpnState !== 'connected') {
        speedDown.textContent = '0.0 KB/s';
        speedUp.textContent = '0.0 KB/s';
        return;
      }
      try {
        const status = await invoke('get_vpn_status');
        if (status && status.state === 'connected') {
          const now = Date.now();
          const dt = Math.max(1, (now - lastPollTime) / 1000);
          lastPollTime = now;
          if (status.bytes_received !== undefined && status.bytes_sent !== undefined) {
            const rxRate = Math.max(0, (status.bytes_received - lastBytesDown) / dt);
            const txRate = Math.max(0, (status.bytes_sent - lastBytesUp) / dt);
            lastBytesDown = status.bytes_received;
            lastBytesUp = status.bytes_sent;
            speedDown.textContent = formatBytesPerSec(rxRate);
            speedUp.textContent = formatBytesPerSec(txRate);
          } else {
            speedDown.textContent = '0.0 KB/s';
            speedUp.textContent = '0.0 KB/s';
          }
        }
      } catch (_) {}
    }, 1000);
  }

  function stopSpeedMeters() {
    if (speedInterval) clearInterval(speedInterval);
    speedInterval = null;
    speedDown.textContent = '0.0 KB/s';
    speedUp.textContent = '0.0 KB/s';
  }

  // Real backend state synchronization loop (R-12, H9, H2)
  async function pollVpnStatus() {
    try {
      const status = await invoke('get_vpn_status');
      if (!status || !status.state) return;

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

  // Power Button Action with real cancellation
  powerButton.addEventListener('click', async () => {
    if (!isAuthenticated) {
      showScreen('screen-login');
      return;
    }

    if (vpnState === 'disconnected' || vpnState === 'failed') {
      const mode = settingTunnelMode ? settingTunnelMode.value : 'proxy_only';
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
        } else {
          const err = (res && res.error) ? res.error : 'Connection initiation failed';
          log(`Failed to initiate connect: ${err}`);
          setVpnState('failed', err);
        }
      } catch (err) {
        log(`Connection exception: ${err}`);
        setVpnState('failed', err.toString());
      }
    } else if (vpnState === 'connecting' || vpnState === 'reconnecting') {
      log('User cancelled connection in progress.');
      setVpnState('disconnecting');
      await invoke('disconnect_vpn');
      setVpnState('disconnected');
    } else {
      log('Disconnecting VPN...');
      setVpnState('disconnecting');
      await invoke('disconnect_vpn');
      setVpnState('disconnected');
    }
  });

  // ==================== SERVER LIST ====================
  const FALLBACK_SERVERS = [
    { countryCode: 'REC', countryName: 'Recommended', cityName: 'Fastest Edge Node', latency: '-- ms' },
    { countryCode: 'DE', countryName: 'Germany', cityName: 'Frankfurt', latency: '-- ms' },
    { countryCode: 'US', countryName: 'United States', cityName: 'New York', latency: '-- ms' },
    { countryCode: 'NL', countryName: 'Netherlands', cityName: 'Amsterdam', latency: '-- ms' },
    { countryCode: 'GB', countryName: 'United Kingdom', cityName: 'London', latency: '-- ms' },
    { countryCode: 'FR', countryName: 'France', cityName: 'Paris', latency: '-- ms' },
    { countryCode: 'CA', countryName: 'Canada', cityName: 'Montreal', latency: '-- ms' },
    { countryCode: 'CH', countryName: 'Switzerland', cityName: 'Zurich', latency: '-- ms' }
  ];

  async function fetchServerList() {
    try {
      const res = await invoke('fetch_server_list');
      if (res && res.success && res.countries && res.countries.length > 0) {
        serverList = [FALLBACK_SERVERS[0]]; // Recommended first
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
        serverList = FALLBACK_SERVERS;
      }
    } catch (e) {
      serverList = FALLBACK_SERVERS;
    }
    renderServers(serverList);
  }

  function renderServers(list) {
    if (!serverListContainer) return;
    while (serverListContainer.firstChild) {
      serverListContainer.removeChild(serverListContainer.firstChild);
    }
    list.forEach(item => {
      const row = document.createElement('div');
      row.className = 'server-item';

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

      row.addEventListener('click', () => {
        selectedServer = item;
        currentLocationTitle.textContent = item.countryName;
        currentLocationSub.textContent = item.cityName;
        currentLatency.textContent = item.latency;
        closeDrawer(modalServers);
        log(`Selected Server: ${item.countryName} - ${item.cityName}`);
      });
      serverListContainer.appendChild(row);
    });
  }

  if (serverSearch) {
    serverSearch.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = serverList.filter(s => 
        s.countryName.toLowerCase().includes(q) || s.cityName.toLowerCase().includes(q)
      );
      renderServers(filtered);
    });
  }

  // Drawer event listeners
  btnSelectLocation.addEventListener('click', () => {
    if (serverList.length === 0) {
      serverList = FALLBACK_SERVERS;
      renderServers(serverList);
      fetchServerList();
    }
    openDrawer(modalServers);
  });
  btnCloseServers.addEventListener('click', () => closeDrawer(modalServers));

  btnOpenSettings.addEventListener('click', () => {
    updateAccountDisplay();
    openDrawer(modalSettings);
  });
  btnCloseSettings.addEventListener('click', () => closeDrawer(modalSettings));

  btnOpenLogs.addEventListener('click', () => openDrawer(modalLogs));
  btnCloseLogs.addEventListener('click', () => closeDrawer(modalLogs));

  // Theme Toggle
  btnThemeToggle.addEventListener('click', () => {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);
  });

  // ==================== INITIALIZATION ====================
  log('iFoxy Windows Desktop Engine Initialized');
  log('Native Subsystem: Active (No Terminal)');
  log('Routing: Wintun L3 Full-System TUN + WinINet Proxy');

  // Start with Splash screen for 600ms, then check auth state
  setTimeout(() => {
    checkAuthState();
    statusPollInterval = setInterval(pollVpnStatus, 1000);
  }, 600);
})();
