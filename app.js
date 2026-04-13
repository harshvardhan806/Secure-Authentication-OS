const STATE = {
    user: null,
    isAuthorized: false,
    activeView: 'sys-overview',
    threatLevel: 12,
    bootCompleted: false,
    mfaSeed: "AEGIS-" + Math.random().toString(36).substring(7).toUpperCase(),
    totpRef: "000 000",
    authStage: "signin" // signin -> login -> mfa -> dashboard
};

const STORAGE_KEYS = {
    enrolledUser: "aegis.enrolledUser.v1"
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initBootSequence();
    initNavigation();
    initClock();
    initThreatChart();
    initAttackLab();
    initPolicyManager();
    document.getElementById('totp-seed').innerText = STATE.mfaSeed;
    initAuthUI();
});

// --- State & Navigation ---
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(pageId).classList.add('active');
}

function setAuthStage(stage) {
    STATE.authStage = stage;
    const signin = document.getElementById('signin-container');
    const login = document.getElementById('login-container');
    const mfa = document.getElementById('mfa-container');

    // Reset messages and styling
    const signinMsg = document.getElementById('signin-msg');
    const loginMsg = document.getElementById('login-msg');
    if (signinMsg) signinMsg.innerText = "";
    if (loginMsg) loginMsg.innerText = "";
    document.getElementById('mfa-input').style.borderColor = 'var(--border)';

    signin.style.display = stage === "signin" ? "block" : "none";
    login.style.display = stage === "login" ? "block" : "none";
    mfa.style.display = stage === "mfa" ? "block" : "none";
}

function getEnrolledUser() {
    try {
        const raw = localStorage.getItem(STORAGE_KEYS.enrolledUser);
        return raw ? JSON.parse(raw) : null;
    } catch {
        return null;
    }
}

function setEnrolledUser(userRecord) {
    localStorage.setItem(STORAGE_KEYS.enrolledUser, JSON.stringify(userRecord));
}

function clearEnrolledUser() {
    localStorage.removeItem(STORAGE_KEYS.enrolledUser);
}

function setAuthMessage(elId, msg, type = "info") {
    const el = document.getElementById(elId);
    if (!el) return;
    const color = type === "danger" ? "var(--accent)" : (type === "warn" ? "var(--secondary)" : "var(--primary)");
    el.style.color = color;
    el.innerText = msg;
}

async function sha256Hex(input) {
    const data = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes = 16) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return [...buf].map(b => b.toString(16).padStart(2, "0")).join("");
}

function initAuthUI() {
    const goLogin = document.getElementById('go-login');
    const goSignin = document.getElementById('go-signin');

    goLogin.addEventListener('click', () => setAuthStage("login"));
    goSignin.addEventListener('click', () => setAuthStage("signin"));

    const enrolled = getEnrolledUser();
    setAuthStage("signin");

    // If a user is enrolled, prefill username to reduce friction
    if (enrolled?.username) {
        const loginUser = document.getElementById('username');
        loginUser.value = enrolled.username;
    }

    // Hook up sign-in (enrollment)
    document.getElementById('signin-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('signin-username').value.trim();
        const pass = document.getElementById('signin-password').value;
        const pass2 = document.getElementById('signin-password-confirm').value;

        if (username.length < 3) {
            setAuthMessage("signin-msg", "Username must be at least 3 characters.", "warn");
            return;
        }
        if (pass !== pass2) {
            setAuthMessage("signin-msg", "Key phrases do not match.", "danger");
            return;
        }

        const salt = randomHex(16);
        const passHash = await sha256Hex(`${username}:${salt}:${pass}`);
        setEnrolledUser({
            username,
            salt,
            passHash,
            createdAt: new Date().toISOString()
        });

        addLog(`Enroll: Identity provisioned for ${username}`);
        setAuthMessage("signin-msg", "Identity created. Proceed to Login.", "info");

        // Prefill login and move to login stage
        document.getElementById('username').value = username;
        document.getElementById('password').value = "";
        setAuthStage("login");
    });
}

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (!STATE.isAuthorized) {
                addLog("Auth: Navigation blocked (unauthorized).", "warn");
                showPage('auth-page');
                setAuthStage("signin");
                return;
            }
            const target = item.getAttribute('data-target');
            document.querySelectorAll('.view-panel').forEach(v => v.style.display = 'none');
            document.getElementById(target).style.display = 'block';
            
            document.querySelectorAll('.nav-item').forEach(ni => ni.classList.remove('active'));
            item.classList.add('active');
            
            addLog(`Navigation: Accessing ${target.replace('-', ' ').toUpperCase()}`);
        });
    });
}

// --- Internal Boot Sequence ---
async function initBootSequence() {
    const terminal = document.getElementById('boot-terminal');
    const logs = [
        "AEGIS BIOS v4.2.0-SAFE (Build 2026.04.08)",
        "CPU: Integrated Quantum Neural Processor @ 5.2GHz",
        "Memory: 1024TB Hyper-Entangled RAM... OK",
        "Storage: 10PB Holographic SSD... OK",
        "Initializing Kernel...",
        "Loading [ASLR] Address Space Layout Randomization... SUCCESS",
        "Loading [DEP] Data Execution Prevention... ENABLED",
        "Configuring [IOMMU] Input-Output Memory Management Unit...",
        "Checking for unauthorized trapdoors...",
        "Kernel Secure Boot: Verified Signature",
        "System Integrity Check: 100% Nominal",
        "Starting Aegis OS Authentication Gate..."
    ];

    for (const log of logs) {
        const line = document.createElement('div');
        line.innerText = `[ ${new Date().toLocaleTimeString()} ] ${log}`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
        await new Promise(r => setTimeout(r, Math.random() * 400 + 100));
    }

    await new Promise(r => setTimeout(r, 1000));
    showPage('auth-page');
    setAuthStage("signin");
}

// --- Authentication Engine ---
document.getElementById('login-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value;

    const enrolled = getEnrolledUser();
    if (!enrolled) {
        setAuthMessage("login-msg", "No enrolled identity found. Sign in first.", "warn");
        setAuthStage("signin");
        return;
    }
    if (username !== enrolled.username) {
        setAuthMessage("login-msg", "Unknown username for this device. Use the enrolled username.", "danger");
        return;
    }
    
    // Simulate Argon2 Hashing
    addLog(`Auth: Requesting session for ${username}`);
    addLog(`Crypto: Computing Argon2id hash (Salt: ${STATE.mfaSeed})...`);
    
    (async () => {
        const candidateHash = await sha256Hex(`${username}:${enrolled.salt}:${pass}`);
        if (candidateHash !== enrolled.passHash) {
            setAuthMessage("login-msg", "Access denied: invalid key phrase.", "danger");
            addLog("Auth: Invalid credentials detected.", "danger");
            return;
        }

        // Credentials ok -> advance to MFA
        setTimeout(() => {
            setAuthStage("mfa");
            startTOTPTimer();
        }, 900);
    })();
});

function startTOTPTimer() {
    const codeEl = document.getElementById('active-totp');
    const timerBar = document.getElementById('totp-timer');
    
    function refresh() {
        const newCode = Math.floor(100000 + Math.random() * 900000).toString().replace(/(\d{3})(\d{3})/, '$1 $2');
        STATE.totpRef = newCode;
        codeEl.innerText = newCode;
        
        let width = 100;
        const interval = setInterval(() => {
            width -= 1;
            timerBar.style.width = width + '%';
            if (width <= 0) {
                clearInterval(interval);
                refresh();
            }
        }, 100);
    }
    refresh();
}

document.getElementById('verify-mfa').addEventListener('click', () => {
    const input = document.getElementById('mfa-input').value.trim();
    if (input === STATE.totpRef || input.replace(" ", "") === STATE.totpRef.replace(" ", "")) {
        addLog("Auth: MFA Token Verified. Loading Secure Environment.");
        STATE.isAuthorized = true;
        showPage('dashboard-page');
        initDashboard();
    } else {
        addLog("Alert: Invalid MFA token detected. Integrity check failed.", "danger");
        document.getElementById('mfa-input').style.borderColor = 'var(--accent)';
    }
});

// --- Dashboard Logic ---
function initDashboard() {
    const modules = [
        { name: "Auth Kernel", status: "Secure", desc: "Argon2 Hardened" },
        { name: "MemProtect", status: "Enabled", desc: "DEP/ASLR Active" },
        { name: "PrivGuard", status: "Shielded", desc: "Ring-3 Sandbox" },
        { name: "TrapdoorScan", status: "Monitoring", desc: "Heuristic Check" },
        { name: "I/O Filter", status: "Locked", desc: "Traffic Scrubbing" }
    ];

    const grid = document.getElementById('module-grid');
    grid.innerHTML = '';
    modules.forEach(mod => {
        const el = document.createElement('div');
        el.className = 'glass-card';
        el.style.padding = '0.75rem';
        el.innerHTML = `
            <p style="font-size:0.7rem; color: var(--primary);">${mod.status}</p>
            <p style="font-weight: bold; font-size: 0.9rem;">${mod.name}</p>
            <p style="font-size: 0.7rem; opacity: 0.6;">${mod.desc}</p>
        `;
        el.addEventListener('mouseenter', () => {
            document.getElementById('ai-status').innerText = `Diagnostic: ${mod.name} is ${mod.status}. Coverage: 100%.`;
        });
        grid.appendChild(el);
    });
}

// --- Attack Lab ---
function initAttackLab() {
    const memoryMap = document.getElementById('memory-map');
    const input = document.getElementById('overflow-input');
    const result = document.getElementById('overflow-result');

    // Create 32 memory slots
    for (let i = 0; i < 32; i++) {
        const slot = document.createElement('div');
        slot.className = 'memory-slot';
        if (i === 24) slot.classList.add('canary'); // Stack Canary
        if (i > 24) slot.classList.add('resv'); // Instruction Pointer area
        slot.innerText = '0x' + (i * 4).toString(16).padStart(2, '0');
        memoryMap.appendChild(slot);
    }

    input.addEventListener('input', () => {
        const val = input.value;
        const slots = document.querySelectorAll('.memory-slot');
        
        slots.forEach((s, idx) => {
            s.classList.remove('filled', 'overflow');
            s.innerText = '0x' + (idx * 4).toString(16).padStart(2, '0');
            
            if (idx < val.length) {
                s.classList.add('filled');
                s.innerText = val[idx];
            }
            
            if (idx >= 24 && idx < val.length) {
                s.classList.add('overflow');
                result.innerHTML = `<span style="color:var(--accent)">CRITICAL: Stack Canary Overwritten! EXECUTION HALTED.</span>`;
                addLog("Security Alert: Buffer Overflow detected on user process.", "danger");
                STATE.threatLevel = 80;
            } else if (val.length < 24) {
                result.innerText = val.length > 0 ? `Buffer occupancy: ${val.length}/24 bytes. System safe.` : "";
                STATE.threatLevel = 12;
            }
        });
    });

    // Privilege Escalation
    document.getElementById('escalate-btn').addEventListener('click', () => {
        const res = document.getElementById('priv-result');
        res.innerHTML = "Requesting EUID=0 elevation...<br>";
        addLog("System: Unauthorized privilege escalation attempt detected.");
        
        setTimeout(() => {
            res.innerHTML += "<span style='color:var(--accent)'>PERMISSION DENIED: Aegis Kernel Guard blocked unauthorized Ring-0 transition. Incident reported.</span>";
            STATE.threatLevel = 50;
        }, 1000);
    });
}

// --- Policy Manager ---
function initPolicyManager() {
    const passInput = document.getElementById('password');
    function update(val) {
        const policies = {
            min8: val.length >= 8,
            special: /[!@#$%^&*(),.?":{}|<>]/.test(val),
            numeric: /[0-9]/.test(val),
            case: /[a-z]/.test(val) && /[A-Z]/.test(val)
        };

        for (const [key, met] of Object.entries(policies)) {
            const el = document.querySelector(`[data-policy="${key}"]`);
            if (!el) continue;
            if (met) {
                el.style.color = 'var(--primary)';
                el.innerHTML = '✔ ' + el.innerText.replace('✔ ', '').replace('✖ ', '');
            } else {
                el.style.color = 'rgba(255,255,255,0.3)';
                el.innerHTML = '✖ ' + el.innerText.replace('✔ ', '').replace('✖ ', '');
            }
        }
    }

    passInput.addEventListener('input', () => update(passInput.value));
}

// --- Utilities ---
function addLog(msg, type = 'info') {
    const logContainer = document.getElementById('audit-log');
    if (!logContainer) return;
    const line = document.createElement('div');
    line.style.marginBottom = '4px';
    const color = type === 'danger' ? 'var(--accent)' : (type === 'warn' ? 'var(--secondary)' : '#e2e8f0');
    line.innerHTML = `<span style="opacity:0.3">[ ${new Date().toLocaleTimeString()} ]</span> <span style="color:${color}">${msg}</span>`;
    logContainer.prepend(line);
}

function initClock() {
    const el = document.getElementById('system-time');
    setInterval(() => {
        el.innerText = "LOCAL_TIME: " + new Date().toLocaleString();
    }, 1000);
}

function initThreatChart() {
    const chart = document.querySelector('.scanning');
    setInterval(() => {
        const bars = document.querySelectorAll('.threat-bar');
        bars.forEach(b => b.remove());
        
        for (let i = 0; i < 20; i++) {
            const h = Math.random() * STATE.threatLevel + 10;
            const bar = document.createElement('div');
            bar.className = 'threat-bar';
            bar.style.position = 'absolute';
            bar.style.bottom = '0';
            bar.style.left = (i * 5) + '%';
            bar.style.width = '3%';
            bar.style.height = h + '%';
            bar.style.background = STATE.threatLevel > 40 ? 'var(--accent)' : 'var(--primary)';
            bar.style.opacity = '0.5';
            chart.appendChild(bar);
        }
        
        // Update bars
        document.getElementById('cpu-bar').style.width = Math.min(100, (Math.random() * 5 + 10)) + '%';
        document.getElementById('mem-bar').style.width = Math.min(100, (80 + Math.random() * 10)) + '%';

    }, 1000);
}