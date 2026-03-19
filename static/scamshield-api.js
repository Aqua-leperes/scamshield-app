/* ============================================================
   ScamShield API Connector
   Drop this file into your static/ folder and add this line
   just before </body> in scamshield_v13.html:
   <script src="/static/scamshield-api.js"></script>
   ============================================================ */

const API = 'http://127.0.0.1:5000/api';

/* ─── Current logged-in user (stored in memory) ─────────── */
let apiUser = null;  // will hold { user_id, name, email, role, plan_id }

/* ─── Helper: show a loading state on a button ──────────── */
function btnLoading(id, text) {
  var btn = document.getElementById(id);
  if (btn) { btn.disabled = true; btn.textContent = text; }
}
function btnReset(id, text) {
  var btn = document.getElementById(id);
  if (btn) { btn.disabled = false; btn.textContent = text; }
}


/* ══════════════════════════════════════════════════════════
   LOGIN  —  replaces the dummy handleLogin()
   ══════════════════════════════════════════════════════════ */
window.handleLogin = function() {
  var email = document.getElementById('login-email').value.trim();
  var pass  = document.getElementById('login-pass').value;
  var ok = true;

  if (!email || !email.includes('@')) { showFieldError('login-email-err', true); ok = false; }
  else { showFieldError('login-email-err', false); }
  if (!pass) { showFieldError('login-pass-err', true); ok = false; }
  else { showFieldError('login-pass-err', false); }
  if (!ok) return;

  btnLoading('login-btn', 'Signing in...');

  fetch(API + '/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: pass })
  })
  .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
  .then(function(r) {
    btnReset('login-btn', 'Sign In →');
    if (!r.ok) {
      showToast(r.data.error || 'Login failed', 'danger');
      return;
    }
    apiUser = r.data.user;
    currentUser = { name: apiUser.name, email: apiUser.email };
    launchApp();
    showToast('Welcome back, ' + apiUser.name.split(' ')[0] + '!', 'success');
    loadDashboardData();
  })
  .catch(function() {
    btnReset('login-btn', 'Sign In →');
    showToast('Could not connect to server. Is Flask running?', 'danger');
  });
};


/* ══════════════════════════════════════════════════════════
   SIGNUP  —  replaces the dummy handleSignup()
   ══════════════════════════════════════════════════════════ */
window.handleSignup = function() {
  var name    = document.getElementById('signup-name').value.trim();
  var email   = document.getElementById('signup-email').value.trim();
  var pass    = document.getElementById('signup-pass').value;
  var confirm = document.getElementById('signup-confirm').value;
  var ok = true;

  if (!name)               { showFieldError('signup-name-err',    true); ok = false; } else { showFieldError('signup-name-err',    false); }
  if (!email.includes('@')){ showFieldError('signup-email-err',   true); ok = false; } else { showFieldError('signup-email-err',   false); }
  if (pass.length < 6)    { showFieldError('signup-pass-err',    true); ok = false; } else { showFieldError('signup-pass-err',    false); }
  if (pass !== confirm)   { showFieldError('signup-confirm-err', true); ok = false; } else { showFieldError('signup-confirm-err', false); }
  if (!ok) return;

  btnLoading('signup-btn', 'Creating account...');

  fetch(API + '/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name, email: email, password: pass })
  })
  .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
  .then(function(r) {
    btnReset('signup-btn', 'Create Account →');
    if (!r.ok) {
      showToast(r.data.error || 'Registration failed', 'danger');
      return;
    }
    /* Auto-login after signup */
    apiUser = { user_id: r.data.user_id, name: name, email: email };
    currentUser = { name: name, email: email };
    launchApp();
    showToast('Welcome to ScamShield, ' + name.split(' ')[0] + '!', 'success');
  })
  .catch(function() {
    btnReset('signup-btn', 'Create Account →');
    showToast('Could not connect to server. Is Flask running?', 'danger');
  });
};


/* ══════════════════════════════════════════════════════════
   SCAN  —  replaces the dummy runScan()
   ══════════════════════════════════════════════════════════ */
window.runScan = function() {
  if (window.scanning) return;
  var text = document.getElementById('scan-text').value.trim();
  if (!text) { showToast('Please paste a message to scan', 'warn'); return; }

  if (!apiUser) {
    showToast('Please log in to scan messages', 'warn');
    return;
  }

  window.scanning = true;
  document.getElementById('scan-btn').textContent = 'Scanning...';
  document.getElementById('scan-progress').style.display = 'block';
  document.getElementById('scan-result-box').style.display = 'none';

  /* Animate the progress bar while waiting for API */
  var pct = 0;
  var stages = document.querySelectorAll('.scan-stage');
  var interval = setInterval(function() {
    pct = Math.min(pct + Math.random() * 10 + 4, 90);
    document.getElementById('scan-pct').textContent = Math.round(pct) + '%';
    document.getElementById('scan-fill').style.width = pct + '%';
    stages.forEach(function(s, i) { if (pct > (i + 1) * 24) s.classList.add('done'); });
  }, 120);

  /* Map the UI scan type buttons to API values */
  var typeMap = { email: 'Email', sms: 'SMS', url: 'URL', whatsapp: 'WhatsApp' };
  var scanType = typeMap[window.currentScanType || 'email'] || 'SMS';

  fetch(API + '/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id:    apiUser.user_id,
      input_text: text,
      scan_type:  scanType
    })
  })
  .then(function(res) { return res.json(); })
  .then(function(data) {
    clearInterval(interval);
    document.getElementById('scan-pct').textContent = '100%';
    document.getElementById('scan-fill').style.width = '100%';
    stages.forEach(function(s) { s.classList.add('done'); });

    setTimeout(function() {
      var score  = parseFloat(data.confidence_score) || 0;
      var isScam = data.result === 'SCAM';

      /* Reuse the existing showScanResult display logic */
      var box = document.getElementById('scan-result-box');
      box.className = 'scan-result-box ' + (isScam ? 'scam' : 'safe');
      document.getElementById('scan-result-icon').textContent  = isScam ? '⚠️' : '✅';
      document.getElementById('scan-result-label').textContent = isScam ? 'Likely Scam' : 'Looks Safe';
      document.getElementById('scan-result-label').style.color = isScam ? 'var(--danger)' : 'var(--success)';
      document.getElementById('scan-result-conf').textContent  = 'Confidence: ' + Math.round(score) + '%';
      document.getElementById('scan-result-score').textContent = Math.round(score) + '%';
      document.getElementById('scan-result-score').style.color = isScam ? 'var(--danger)' : 'var(--success)';
      document.getElementById('scan-result-text').textContent  = isScam
        ? 'This message shows patterns associated with scam content. Do not click links or share personal information.'
        : 'No strong scam indicators found. Remain cautious and verify the sender independently.';

      var fill = document.getElementById('risk-fill');
      if (fill) {
        fill.style.background = isScam
          ? 'linear-gradient(90deg,var(--danger),#f05545)'
          : 'linear-gradient(90deg,var(--success),#28d68a)';
        fill.style.width = '0';
        setTimeout(function() { fill.style.width = score + '%'; }, 100);
      }

      box.style.display = 'block';
      document.getElementById('scan-progress').style.display = 'none';
      document.getElementById('scan-btn').textContent = 'Scan Message';
      window.scanning = false;

      /* Add to local scan history display */
      var histEntry = {
        text:   text.slice(0, 60) + (text.length > 60 ? '...' : ''),
        score:  Math.round(score),
        result: data.result,
        type:   scanType,
        date:   'Just now'
      };
      if (window.scanHistoryData) {
        scanHistoryData.unshift(histEntry);
        if (scanHistoryData.length > 5) scanHistoryData.pop();
        renderScanHistory();
      }

      showToast(
        isScam ? 'Scam detected! Risk: ' + Math.round(score) + '%' : 'Message looks safe',
        isScam ? 'danger' : 'success'
      );
    }, 400);
  })
  .catch(function() {
    clearInterval(interval);
    window.scanning = false;
    document.getElementById('scan-progress').style.display = 'none';
    document.getElementById('scan-btn').textContent = 'Scan Message';
    showToast('Scan failed. Is Flask running?', 'danger');
  });
};


/* ══════════════════════════════════════════════════════════
   SUBMIT REPORT  —  replaces the dummy submitReport()
   ══════════════════════════════════════════════════════════ */
window.submitReport = function() {
  var text     = document.getElementById('report-text').value.trim();
  var category = document.getElementById('report-type') ? document.getElementById('report-type').value : 'Other';

  if (!text) { showToast('Please enter message content', 'warn'); return; }
  if (!apiUser) { showToast('Please log in to submit reports', 'warn'); return; }

  fetch(API + '/reports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id:     apiUser.user_id,
      category:    category,
      description: text,
      risk_level:  'Medium'
    })
  })
  .then(function(res) { return res.json(); })
  .then(function(data) {
    document.getElementById('report-form-wrap').style.display = 'none';
    document.getElementById('report-success').style.display = 'block';
    showToast('Report ' + (data.report_id || '') + ' submitted!', 'success');
  })
  .catch(function() {
    showToast('Could not submit report. Is Flask running?', 'danger');
  });
};


/* ══════════════════════════════════════════════════════════
   SEND CONTACT  —  replaces the dummy sendContact()
   ══════════════════════════════════════════════════════════ */
window.sendContact = function() {
  var name     = document.getElementById('ct-name').value.trim();
  var email    = document.getElementById('ct-email').value.trim();
  var subject  = document.getElementById('ct-subject').value.trim() || 'ScamShield Support Request';
  var type     = document.getElementById('ct-type') ? document.getElementById('ct-type').value : 'General';
  var priority = document.getElementById('ct-priority') ? document.getElementById('ct-priority').value : 'Normal';
  var msg      = document.getElementById('ct-message').value.trim();

  if (!name || !email || !msg) { showToast('Please fill in all required fields', 'warn'); return; }
  if (!email.includes('@'))    { showToast('Please enter a valid email address', 'warn'); return; }

  btnLoading('ct-send-btn', 'Sending...');

  fetch(API + '/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id:  apiUser ? apiUser.user_id : null,
      name:     name,
      email:    email,
      subject:  subject,
      type:     'contact',
      category: type,
      priority: priority,
      message:  msg
    })
  })
  .then(function(res) { return res.json(); })
  .then(function() {
    btnReset('ct-send-btn', 'Send Message');
    document.getElementById('contact-form-inner').style.display = 'none';
    document.getElementById('ct-thankyou-name').textContent  = name;
    document.getElementById('ct-thankyou-email').textContent = email;
    var s = document.getElementById('contact-success');
    if (s) s.classList.add('show');
    showToast('Message sent! We will respond within 24 hours.', 'success');
  })
  .catch(function() {
    btnReset('ct-send-btn', 'Send Message');
    showToast('Could not send message. Is Flask running?', 'danger');
  });
};


/* ══════════════════════════════════════════════════════════
   LOAD ALL USER DATA after login
   ══════════════════════════════════════════════════════════ */
function loadDashboardData() {
  if (!apiUser) return;
  loadUserProfile();
  loadScanHistory();
  loadUserReports();
  loadNotifications();
}

/* ── Load & populate profile fields ──────────────────────── */
function loadUserProfile() {
  fetch(API + '/user/' + apiUser.user_id)
  .then(function(res) { return res.json(); })
  .then(function(u) {
    apiUser = Object.assign(apiUser, u);
    /* Populate settings fields */
    var fields = {
      'st-name':       u.name        || '',
      'st-email':      u.email       || '',
      'st-phone':      u.phone       || '',
      'st-dob':        u.date_of_birth ? u.date_of_birth.slice(0,10) : '',
      'st-country':    u.country     || '',
      'st-location':   u.location    || '',
      'st-timezone':   u.timezone    || 'EAT',
      'st-occupation': u.occupation  || '',
      'st-usecase':    u.use_case    || '',
      'st-bio':        u.bio         || ''
    };
    Object.keys(fields).forEach(function(id) {
      var el = document.getElementById(id);
      if (el) el.value = fields[id];
    });
    /* Update nav avatar initials */
    var initials = u.name ? u.name.split(' ').map(function(w){ return w[0]; }).join('').slice(0,2).toUpperCase() : 'U';
    var navAvatar = document.getElementById('nav-avatar');
    if (navAvatar) navAvatar.textContent = initials;
  })
  .catch(function() {});
}

/* ── Save profile to database ────────────────────────────── */
window.saveProfile = function() {
  if (!apiUser) { showToast('Please log in first', 'warn'); return; }

  var data = {
    name:         (document.getElementById('st-name')       || {}).value || '',
    email:        (document.getElementById('st-email')      || {}).value || '',
    phone:        (document.getElementById('st-phone')      || {}).value || '',
    date_of_birth:(document.getElementById('st-dob')        || {}).value || null,
    country:      (document.getElementById('st-country')    || {}).value || '',
    location:     (document.getElementById('st-location')   || {}).value || '',
    timezone:     (document.getElementById('st-timezone')   || {}).value || '',
    occupation:   (document.getElementById('st-occupation') || {}).value || '',
    use_case:     (document.getElementById('st-usecase')    || {}).value || '',
    bio:          (document.getElementById('st-bio')        || {}).value || ''
  };

  fetch(API + '/user/' + apiUser.user_id + '/update', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  .then(function(res) { return res.json(); })
  .then(function() {
    apiUser.name  = data.name;
    apiUser.email = data.email;
    if (window.currentUser) { currentUser.name = data.name; currentUser.email = data.email; }
    if (window.updateNavUser) updateNavUser();
    if (window.initSettings) initSettings();
    var s = document.getElementById('profile-saved');
    if (s) { s.style.display = 'inline'; setTimeout(function(){ s.style.display = 'none'; }, 2500); }
    /* Update nav initials */
    var initials = data.name.split(' ').map(function(w){ return w[0]; }).join('').slice(0,2).toUpperCase();
    var navAvatar = document.getElementById('nav-avatar');
    if (navAvatar) navAvatar.textContent = initials;
    showToast('Profile saved!', 'success');
  })
  .catch(function() { showToast('Could not save profile', 'danger'); });
};


/* ── Load scan history ───────────────────────────────────── */
function loadScanHistory() {
  fetch(API + '/scans/' + apiUser.user_id)
  .then(function(res) { return res.json(); })
  .then(function(scans) {
    window.scanHistoryData = scans.slice(0, 10).map(function(s) {
      return {
        text:   (s.input_text || '').slice(0, 60) + (s.input_text && s.input_text.length > 60 ? '...' : ''),
        score:  Math.round(parseFloat(s.confidence_score) || 0),
        result: s.result,
        type:   s.scan_type,
        date:   s.created_at ? s.created_at.slice(0, 10) : ''
      };
    });
    if (window.renderScanHistory) renderScanHistory();
  })
  .catch(function() {});
}


/* ── Load user reports ───────────────────────────────────── */
function loadUserReports() {
  fetch(API + '/reports/' + apiUser.user_id)
  .then(function(res) { return res.json(); })
  .then(function(reports) {
    /* Map to the format renderReports() expects */
    window.reportsData = reports.map(function(r) {
      var score = r.risk_level === 'High' ? 85 : r.risk_level === 'Medium' ? 55 : 20;
      return {
        date:     r.created_at ? r.created_at.slice(0,10) : '',
        type:     r.category   || 'Report',
        source:   r.report_id  || '—',
        category: r.category   || '—',
        score:    score,
        result:   r.risk_level === 'High' ? 'SCAM' : 'SAFE',
        status:   r.status     || 'Pending'
      };
    });
    if (window.renderReports) renderReports();
  })
  .catch(function() {});
}


/* ── Load notifications ──────────────────────────────────── */
function loadNotifications() {
  fetch(API + '/notifications/' + apiUser.user_id)
  .then(function(res) { return res.json(); })
  .then(function(notifs) {
    var unread = notifs.filter(function(n) { return !n.is_read; }).length;
    var dot = document.querySelector('.notif-dot');
    if (dot) dot.style.display = unread > 0 ? 'block' : 'none';
  })
  .catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   LOAD PLANS on upgrade page
   ══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function() {
  fetch(API + '/plans')
  .then(function(res) { return res.json(); })
  .then(function(plans) {
    window._apiPlans = plans; /* store for use by upgrade page */
  })
  .catch(function() {});
});

console.log('ScamShield API connector loaded. Server:', API);