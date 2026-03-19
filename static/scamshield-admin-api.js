/* ============================================================
   ScamShield Admin API Connector  —  LIVE DATA VERSION
   Add just before </body> in scamshield_admin_v2__1_.html:
   <script src="/static/scamshield-admin-api.js"></script>
   ============================================================ */

const API = 'http://127.0.0.1:5000/api/admin';
let currentAdminData = null;
let _refreshInterval  = null;

function setText(id, val) {
  var el = document.getElementById(id);
  if (el) el.textContent = (val === null || val === undefined) ? '0' : val;
}


/* ══════════════════════════════════════════════════════════
   ADMIN LOGIN
   ══════════════════════════════════════════════════════════ */
window.doLogin = function() {
  var id   = document.getElementById('admin-id').value.trim();
  var pass = document.getElementById('admin-pass').value;
  var err    = document.getElementById('login-error');
  var errMsg = document.getElementById('login-error-msg');

  document.getElementById('admin-id').classList.remove('error');
  document.getElementById('admin-pass').classList.remove('error');
  err.classList.remove('show');

  if (!id)   { document.getElementById('admin-id').classList.add('error');   errMsg.textContent = 'Please enter your Admin ID.'; err.classList.add('show'); return; }
  if (!pass) { document.getElementById('admin-pass').classList.add('error'); errMsg.textContent = 'Please enter your password.';  err.classList.add('show'); return; }

  var btn = document.getElementById('login-btn');
  btn.textContent = 'Signing in...';
  btn.disabled = true;

  fetch('http://127.0.0.1:5000/api/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ admin_id: id, password: pass })
  })
  .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
  .then(function(r) {
    btn.textContent = 'Sign In'; btn.disabled = false;
    if (!r.ok) {
      errMsg.textContent = r.data.error || 'Invalid credentials.';
      err.classList.add('show');
      document.getElementById('admin-id').classList.add('error');
      document.getElementById('admin-pass').classList.add('error');
      return;
    }
    currentAdminData = r.data.admin;
    var admin    = currentAdminData;
    var initials = admin.name.split(' ').map(function(w){ return w[0]; }).join('').slice(0,2);
    window.currentAdmin = { id: admin.admin_code, name: admin.name, role: admin.role };
    setText('sidebar-avatar',     initials);
    setText('topbar-avatar',      initials);
    setText('sidebar-name',       admin.name);
    setText('sidebar-id-display', 'ID: ' + admin.admin_code);
    setText('topbar-name',        admin.name);
    document.getElementById('login-gate').classList.add('hidden');
    document.getElementById('app-shell').classList.add('visible');
    initApp();
    showToast('Welcome back, ' + admin.name.split(' ')[0] + '!', 'success');
    loadAllAdminData();
    if (_refreshInterval) clearInterval(_refreshInterval);
    _refreshInterval = setInterval(loadAllAdminData, 30000);
  })
  .catch(function() {
    btn.textContent = 'Sign In'; btn.disabled = false;
    errMsg.textContent = 'Could not connect to server. Is Flask running?';
    err.classList.add('show');
  });
};


/* ══════════════════════════════════════════════════════════
   LOAD EVERYTHING  —  called on login + every 30s
   ══════════════════════════════════════════════════════════ */
function loadAllAdminData() {
  loadStats();
  loadUsers();
  loadReports();
  loadScans();
  loadThreats();
  loadInbox();
  loadAudit();
  loadKeywords();
}
window.loadAllAdminData = loadAllAdminData;


/* ══════════════════════════════════════════════════════════
   LIVE STATS  —  replaces every hardcoded number
   ══════════════════════════════════════════════════════════ */
function loadStats() {
  fetch(API + '/stats')
  .then(function(res) { return res.json(); })
  .then(function(s) {
    /* Big stat cards */
    setText('stat-total-users',  s.total_users.toLocaleString());
    setText('stat-total-scams',  s.total_scams.toLocaleString());
    setText('stat-scans-today',  s.scans_today.toLocaleString());
    setText('stat-unread-msgs',  s.unread_messages);
    /* Stat subtitles */
    setText('stat-users-sub',       '▲ ' + s.new_users_week + ' new this week');
    setText('stat-scams-sub',       s.total_scans.toLocaleString() + ' total scans');
    setText('stat-scans-today-sub', 'Detection rate: ' + s.detection_rate + '%');
    setText('stat-unread-sub',      s.urgent_messages + ' urgent');
    /* Sidebar badges */
    setText('inbox-badge',           s.unread_messages);
    setText('sidebar-scans-badge',   s.total_scans > 999 ? (s.total_scans/1000).toFixed(1)+'k' : s.total_scans);
    setText('sidebar-reports-badge', s.total_reports);
    setText('sidebar-threats-badge', s.active_threats);
    /* Detection accuracy */
    setText('stat-detection-rate', s.detection_rate + '%');
    var bar = document.getElementById('stat-detection-bar');
    if (bar) bar.style.width = s.detection_rate + '%';
    /* Reports filter chips */
    setText('chip-reports-all',       'All (' + s.total_reports + ')');
    setText('chip-reports-pending',   '⏳ Pending (' + s.reports_pending + ')');
    setText('chip-reports-review',    '👁️ Under Review (' + s.reports_review + ')');
    setText('chip-reports-resolved',  '✅ Resolved (' + s.reports_resolved + ')');
    setText('chip-reports-dismissed', '❌ Dismissed (' + s.reports_dismissed + ')');
    /* Threats chip */
    setText('chip-threats-new', '🆕 New (' + s.new_threats + ')');
    /* Inbox mini stats */
    setText('inbox-stat-unread',  s.unread_messages);
    setText('inbox-stat-pending', s.reports_pending);
    setText('inbox-stat-total',   s.total_messages);
  })
  .catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   USERS TABLE
   ══════════════════════════════════════════════════════════ */
function loadUsers() {
  fetch(API + '/users')
  .then(function(res) { return res.json(); })
  .then(function(users) {
    var colors = ['#1a6cf6','#e5382a','#22b573','#f5a623','#8b5cf6','#00c2a8','#ec4899'];
    function rColor(i) { return colors[i % colors.length]; }
    function inits(name) { return name.split(' ').map(function(w){ return w[0]; }).join('').slice(0,2).toUpperCase(); }
    if (!users.length) {
      document.getElementById('users-tbody').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3)">No users yet</td></tr>';
      return;
    }
    document.getElementById('users-tbody').innerHTML = users.map(function(u, i) {
      var sB = u.status==='active'?'badge-success':u.status==='suspended'?'badge-danger':'badge-warn';
      var rB = u.role==='admin'?'badge-danger':u.role==='moderator'?'badge-info':'badge-neutral';
      var joined = u.created_at ? u.created_at.slice(0,10) : '';
      return '<tr>' +
        '<td><input type="checkbox"></td>' +
        '<td><div style="display:flex;align-items:center;gap:9px"><div class="user-avatar" style="background:' + rColor(i) + '">' + inits(u.name) + '</div>' +
        '<div><div style="font-weight:700;font-size:12.5px">' + u.name + '</div><div style="font-size:11px;color:var(--text3)">' + u.email + '</div></div></div></td>' +
        '<td class="td-mono">' + u.email + '</td>' +
        '<td><span class="badge ' + rB + '">' + u.role + '</span></td>' +
        '<td><span class="badge ' + sB + '">' + u.status + '</span></td>' +
        '<td class="td-mono">' + (u.scan_count||0).toLocaleString() + '</td>' +
        '<td style="font-size:11.5px;color:var(--text3)">' + joined + '</td>' +
        '<td><div class="row-actions">' +
          '<button class="action-btn view" onclick="showToast(\'Viewing ' + u.name + '\',\'info\')">👁️</button>' +
          (u.status==='active'
            ? '<button class="action-btn del" onclick="adminSuspendUser(\'' + u.user_id + '\',\'' + u.name + '\')">🚫</button>'
            : '<button class="action-btn ok" onclick="adminActivateUser(\'' + u.user_id + '\',\'' + u.name + '\')">✓</button>') +
        '</div></td></tr>';
    }).join('');
  }).catch(function() {});
}

window.adminSuspendUser = function(userId, name) {
  if (!confirm('Suspend ' + name + '?')) return;
  fetch(API + '/users/' + userId + '/suspend', { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ admin_id: currentAdminData ? currentAdminData.admin_id : '' }) })
  .then(function() { showToast(name + ' suspended', 'danger'); loadAllAdminData(); })
  .catch(function() { showToast('Action failed','danger'); });
};
window.adminActivateUser = function(userId, name) {
  fetch(API + '/users/' + userId + '/activate', { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify({}) })
  .then(function() { showToast(name + ' reactivated', 'success'); loadAllAdminData(); })
  .catch(function() { showToast('Action failed','danger'); });
};


/* ══════════════════════════════════════════════════════════
   REPORTS TABLE
   ══════════════════════════════════════════════════════════ */
function loadReports() {
  fetch(API + '/reports')
  .then(function(res) { return res.json(); })
  .then(function(reports) {
    function rB(r) { return r==='Critical'?'badge-danger':r==='High'?'badge-warn':r==='Medium'?'badge-info':'badge-neutral'; }
    function sB(s) { return s==='Pending'?'badge-warn':s==='Under Review'?'badge-info':s==='Resolved'?'badge-success':'badge-neutral'; }
    if (!reports.length) {
      document.getElementById('reports-tbody').innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text3)">No reports yet</td></tr>';
      return;
    }
    document.getElementById('reports-tbody').innerHTML = reports.map(function(r) {
      return '<tr>' +
        '<td class="td-mono">' + r.report_id + '</td>' +
        '<td style="font-weight:600">' + (r.reporter||'Unknown') + '</td>' +
        '<td>' + r.category + '</td>' +
        '<td><span class="badge ' + rB(r.risk_level) + '">' + (r.risk_level||'—') + '</span></td>' +
        '<td><span class="badge ' + sB(r.status) + '">' + r.status + '</span></td>' +
        '<td style="font-size:11.5px;color:var(--text3)">' + (r.created_at||'').slice(0,10) + '</td>' +
        '<td><div class="row-actions">' +
          '<button class="action-btn ok" onclick="adminResolveReport(\'' + r.report_id + '\')">✓</button>' +
          '<button class="action-btn del" onclick="adminDismissReport(\'' + r.report_id + '\')">✕</button>' +
        '</div></td></tr>';
    }).join('');
  }).catch(function() {});
}
window.adminResolveReport = function(id) {
  fetch(API+'/reports/'+id+'/resolve',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_id:currentAdminData?currentAdminData.admin_id:''})})
  .then(function(){ showToast('Report '+id+' resolved','success'); loadAllAdminData(); });
};
window.adminDismissReport = function(id) {
  fetch(API+'/reports/'+id+'/dismiss',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({})})
  .then(function(){ showToast('Report dismissed','warn'); loadAllAdminData(); });
};


/* ══════════════════════════════════════════════════════════
   SCAN LOGS TABLE
   ══════════════════════════════════════════════════════════ */
function loadScans() {
  fetch(API + '/scans')
  .then(function(res) { return res.json(); })
  .then(function(scans) {
    function rB(r) { return r==='SCAM'?'badge-danger':r==='SAFE'?'badge-success':'badge-warn'; }
    if (!scans.length) {
      document.getElementById('scans-tbody').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3)">No scans yet</td></tr>';
      return;
    }
    document.getElementById('scans-tbody').innerHTML = scans.map(function(s) {
      var conf = parseFloat(s.confidence_score)||0;
      var barColor = conf>75?'var(--danger)':conf>40?'var(--warning)':'var(--success)';
      var id = s.scan_id ? 'SCN-'+s.scan_id.slice(0,8).toUpperCase() : '—';
      return '<tr>' +
        '<td class="td-mono">' + id + '</td>' +
        '<td class="td-mono">' + (s.user_email||'—') + '</td>' +
        '<td><span class="badge badge-info">' + s.scan_type + '</span></td>' +
        '<td><span class="badge ' + rB(s.result) + '">' + s.result + '</span></td>' +
        '<td><div style="display:flex;align-items:center;gap:7px"><div class="progress-wrap" style="width:55px"><div class="progress-fill" style="width:'+conf+'%;background:'+barColor+'"></div></div><span class="td-mono">'+Math.round(conf)+'%</span></div></td>' +
        '<td class="td-mono">' + (s.duration_ms ? s.duration_ms+'ms' : '—') + '</td>' +
        '<td class="td-mono">' + (s.created_at||'').slice(11,19) + '</td>' +
        '<td><button class="action-btn view" onclick="showToast(\'Scan detail\',\'info\')">👁️</button></td></tr>';
    }).join('');
  }).catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   THREATS TABLE
   ══════════════════════════════════════════════════════════ */
function loadThreats() {
  fetch(API + '/threats')
  .then(function(res) { return res.json(); })
  .then(function(threats) {
    function sB(s) { return s==='Critical'?'badge-danger':s==='High'?'badge-warn':s==='Medium'?'badge-info':'badge-neutral'; }
    function stB(s) { return s==='Active'?'badge-danger':s==='Monitoring'?'badge-warn':s==='New'?'badge-info':'badge-neutral'; }
    if (!threats.length) {
      document.getElementById('threats-tbody').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3)">No threats yet</td></tr>';
      return;
    }
    document.getElementById('threats-tbody').innerHTML = threats.map(function(t) {
      return '<tr>' +
        '<td class="td-mono" style="font-size:10.5px">' + t.threat_id + '</td>' +
        '<td style="font-weight:700;font-size:12.5px;max-width:180px">' + t.name + '</td>' +
        '<td style="font-size:12px;color:var(--text3)">' + t.category + '</td>' +
        '<td><span class="badge ' + sB(t.severity) + '">' + t.severity + '</span></td>' +
        '<td class="td-mono">' + (t.report_count||0).toLocaleString() + '</td>' +
        '<td><span class="badge ' + stB(t.status) + '">' + t.status + '</span></td>' +
        '<td style="font-size:11.5px;color:var(--text3)">' + (t.updated_at||'').slice(0,10) + '</td>' +
        '<td><div class="row-actions">' +
          '<button class="action-btn view" onclick="showToast(\'Viewing threat\',\'info\')">👁️</button>' +
          '<button class="action-btn edit" onclick="showToast(\'Editing…\',\'info\')">✏️</button>' +
        '</div></td></tr>';
    }).join('');
  }).catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   INBOX
   ══════════════════════════════════════════════════════════ */
function loadInbox(status) {
  var url = API + '/inbox' + (status && status!=='all' ? '?status='+status : '');
  fetch(url)
  .then(function(res) { return res.json(); })
  .then(function(messages) {
    window._adminInboxMessages = messages;
    var listEl = document.querySelector('.inbox-list');
    if (!listEl) return;
    if (!messages.length) {
      listEl.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text3)">📭 No messages yet</div>';
      return;
    }
    listEl.innerHTML = messages.map(function(m) {
      var priColor = m.priority==='Urgent'?'var(--danger)':m.priority==='High'?'var(--warning)':'var(--text3)';
      return '<div class="inbox-item ' + (m.is_unread?'unread':'') + '" onclick="adminOpenMessage('+m.message_id+')">' +
        '<div class="inbox-dot ' + (m.is_unread?'':'read') + '"></div>' +
        '<div style="flex:1;min-width:0">' +
          '<div class="inbox-sender">' + (m.from_name||'Unknown') + '</div>' +
          '<div style="font-size:12.5px;font-weight:600;color:var(--text);margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + (m.subject||'No subject') + '</div>' +
          '<div style="font-size:11px;color:var(--text3);display:flex;gap:8px"><span>' + (m.created_at||'').slice(0,10) + '</span><span style="color:'+priColor+';font-weight:700">' + (m.priority||'Normal') + '</span></div>' +
        '</div></div>';
    }).join('');
  }).catch(function() {});
}

window.adminOpenMessage = function(messageId) {
  fetch(API+'/inbox/'+messageId+'/read',{method:'PATCH'}).catch(function(){});
  var m = (window._adminInboxMessages||[]).find(function(x){ return x.message_id===messageId; });
  if (!m) return;
  var pane = document.querySelector('.inbox-reading') || document.getElementById('inbox-reading-pane');
  if (pane) {
    pane.innerHTML = '<div style="padding:24px">' +
      '<div style="font-size:16px;font-weight:800;margin-bottom:4px">' + (m.subject||'No subject') + '</div>' +
      '<div style="font-size:12px;color:var(--text3);margin-bottom:16px">From: <b>' + (m.from_name||'') + '</b> &lt;' + (m.from_email||'') + '&gt; · ' + (m.created_at||'').slice(0,10) + '</div>' +
      '<div style="font-size:13.5px;color:var(--text2);line-height:1.7;white-space:pre-wrap">' + (m.body||'No content') + '</div>' +
      '<div style="margin-top:20px"><button class="btn-success" style="font-size:12px;padding:8px 16px" onclick="adminResolveMessage('+m.message_id+')">✓ Mark Resolved</button></div>' +
      '</div>';
  }
  loadStats();
};
window.adminResolveMessage = function(id) {
  fetch(API+'/inbox/'+id+'/resolve',{method:'PATCH'})
  .then(function(){ showToast('Message resolved','success'); loadAllAdminData(); });
};
window.switchInboxFolder = function(folder, el) {
  document.querySelectorAll('.inbox-folder').forEach(function(f){ f.classList.remove('active'); });
  if (el) el.classList.add('active');
  loadInbox({all:'all',unread:'Unread',pending:'Pending',resolved:'Resolved'}[folder]||'all');
};


/* ══════════════════════════════════════════════════════════
   AUDIT LOG
   ══════════════════════════════════════════════════════════ */
function loadAudit() {
  fetch(API + '/audit')
  .then(function(res) { return res.json(); })
  .then(function(logs) {
    function sB(s) { return s==='warn'?'badge-warn':s==='success'?'badge-success':s==='danger'?'badge-danger':'badge-info'; }
    function sL(s) { return s==='warn'?'Warning':s==='success'?'Success':s==='danger'?'Danger':'Info'; }
    if (!logs.length) {
      document.getElementById('audit-tbody').innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text3)">No audit entries yet</td></tr>';
      return;
    }
    document.getElementById('audit-tbody').innerHTML = logs.map(function(a) {
      return '<tr>' +
        '<td class="td-mono">' + (a.created_at||'').slice(0,19).replace('T',' ') + '</td>' +
        '<td style="font-weight:600;font-size:12.5px">' + a.admin_name + '</td>' +
        '<td style="font-size:12.5px">' + a.action + '</td>' +
        '<td class="td-mono">' + (a.target||'—') + '</td>' +
        '<td class="td-mono">' + (a.ip_address||'—') + '</td>' +
        '<td><span class="badge ' + sB(a.severity) + '">' + sL(a.severity) + '</span></td></tr>';
    }).join('');
  }).catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   KEYWORDS
   ══════════════════════════════════════════════════════════ */
function loadKeywords() {
  fetch(API + '/keywords')
  .then(function(res) { return res.json(); })
  .then(function(keywords) {
    var el = document.getElementById('banned-keywords');
    if (!el) return;
    if (!keywords.length) {
      el.innerHTML = '<span style="color:var(--text3);font-size:12px">No keywords added yet</span>';
      return;
    }
    el.innerHTML = keywords.map(function(k) {
      var color = k.weight>=0.8?'var(--danger)':k.weight>=0.5?'var(--warning)':'var(--text3)';
      return '<span style="padding:5px 12px;border-radius:20px;font-size:12px;font-weight:700;background:rgba(229,56,42,0.08);color:'+color+';border:1px solid rgba(229,56,42,0.2)" title="Weight: '+k.weight+'">'+k.keyword+'</span>';
    }).join('');
  }).catch(function() {});
}


/* ══════════════════════════════════════════════════════════
   LOGOUT
   ══════════════════════════════════════════════════════════ */
window.doLogout = function() {
  if (!confirm('Sign out of the admin panel?')) return;
  if (_refreshInterval) { clearInterval(_refreshInterval); _refreshInterval = null; }
  currentAdminData = null;
  document.getElementById('app-shell').classList.remove('visible');
  document.getElementById('login-gate').classList.remove('hidden');
  document.getElementById('admin-id').value = '';
  document.getElementById('admin-pass').value = '';
  showToast('Signed out successfully', 'info');
};


/* Expose all functions globally */
window.loadAllAdminData = loadAllAdminData;
window.loadStats        = loadStats;
window.loadUsers        = loadUsers;
window.loadReports      = loadReports;
window.loadScans        = loadScans;
window.loadThreats      = loadThreats;
window.loadInbox        = loadInbox;
window.loadAudit        = loadAudit;
window.loadKeywords     = loadKeywords;

console.log('✅ ScamShield Admin — Live data. Auto-refresh every 30s');