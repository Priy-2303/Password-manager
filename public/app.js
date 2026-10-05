'use strict';

let isRegisterMode = false;
let currentUser = null;
let encryptionKey = null;

const INACTIVITY_LIMIT_SECONDS = 15 * 60;
let remainingInactivitySeconds = INACTIVITY_LIMIT_SECONDS;
let inactivityTimerInterval = null;

let cachedVaultItems = [];
const activeRevealTimers = new Map();

function initAmbientBackground() {
    const canvas = document.getElementById('ambient-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }, { passive: true });

    const particleCount = Math.min(Math.floor(width / 32), 40);
    const particles = [];

    for (let i = 0; i < particleCount; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.25,
            vy: (Math.random() - 0.5) * 0.25,
            size: Math.random() * 1.5 + 0.8,
            alpha: Math.random() * 0.4 + 0.1
        });
    }

    let animationFrameId;

    function renderAmbient() {
        if (document.hidden) {
            animationFrameId = requestAnimationFrame(renderAmbient);
            return;
        }

        ctx.clearRect(0, 0, width, height);
        ctx.strokeStyle = 'rgba(0, 242, 254, 0.04)';
        ctx.lineWidth = 1;

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0) p.x = width;
            if (p.x > width) p.x = 0;
            if (p.y < 0) p.y = height;
            if (p.y > height) p.y = 0;

            ctx.fillStyle = `rgba(0, 242, 254, ${p.alpha})`;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = dx * dx + dy * dy;

                if (dist < 10000) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }
        }

        animationFrameId = requestAnimationFrame(renderAmbient);
    }

    renderAmbient();
}

async function deriveCryptographicKeys(masterPassword, saltHex) {
    const enc = new TextEncoder();
    const safeSalt = (saltHex && typeof saltHex === 'string' && saltHex.length >= 16)
        ? saltHex
        : 'a7c93e4f8b2d1065e8a93b4d1c7e2f50';
    const saltBytes = new Uint8Array(safeSalt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(masterPassword),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: 600000,
            hash: 'SHA-256'
        },
        baseKey,
        512
    );

    const encKeyBits = derivedBits.slice(0, 32);
    const authKeyBits = derivedBits.slice(32, 64);

    const encKey = await window.crypto.subtle.importKey(
        'raw',
        encKeyBits,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );

    const authArray = Array.from(new Uint8Array(authKeyBits));
    const clientAuthHash = authArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return { encKey, clientAuthHash };
}

function generateSecureSalt() {
    const arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptSecretPayload(payload, key) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(JSON.stringify(payload))
    );

    const combined = new Uint8Array(iv.length + new Uint8Array(encrypted).length);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...combined));
}

async function decryptSecretPayload(combinedBase64, key) {
    try {
        const combined = Uint8Array.from(atob(combinedBase64), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        return JSON.parse(new TextDecoder().decode(decrypted));
    } catch {
        return { username: 'CORRUPT_PAYLOAD', password: '***' };
    }
}

function generateCryptographicPassword(length = 20, opts = { upper: true, lower: true, numbers: true, symbols: true }) {
    let charset = '';
    if (opts.upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (opts.lower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (opts.numbers) charset += '0123456789';
    if (opts.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) charset = 'abcdefghijklmnopqrstuvwxyz0123456789';

    const values = new Uint32Array(length);
    window.crypto.getRandomValues(values);

    let result = '';
    for (let i = 0; i < length; i++) {
        result += charset[values[i] % charset.length];
    }
    return result;
}

function resetInactivityTimer() {
    remainingInactivitySeconds = INACTIVITY_LIMIT_SECONDS;
    updateInactivityDisplay();
}

function updateInactivityDisplay() {
    const el = document.getElementById('lock-countdown');
    if (!el) return;
    const mins = Math.floor(remainingInactivitySeconds / 60).toString().padStart(2, '0');
    const secs = (remainingInactivitySeconds % 60).toString().padStart(2, '0');
    el.textContent = `${mins}:${secs}`;
}

function startInactivityDaemon() {
    clearInterval(inactivityTimerInterval);
    remainingInactivitySeconds = INACTIVITY_LIMIT_SECONDS;
    updateInactivityDisplay();

    inactivityTimerInterval = setInterval(() => {
        if (!encryptionKey) return;

        remainingInactivitySeconds--;
        updateInactivityDisplay();

        if (remainingInactivitySeconds <= 0) {
            clearInterval(inactivityTimerInterval);
            executeVaultLock('CRYO-LOCK: Session terminated due to inactivity.');
        }
    }, 1000);
}

['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, () => {
        if (encryptionKey) resetInactivityTimer();
    }, { passive: true });
});

async function playCinematicUnlockSequence() {
    const overlay = document.getElementById('cinematic-overlay');
    overlay.classList.remove('hidden');

    const steps = [
        document.getElementById('seq-step-1'),
        document.getElementById('seq-step-2'),
        document.getElementById('seq-step-3'),
        document.getElementById('seq-step-4'),
        document.getElementById('seq-step-5'),
        document.getElementById('seq-step-6')
    ];

    steps.forEach(s => s.classList.remove('active'));

    for (let i = 0; i < steps.length; i++) {
        await new Promise(r => setTimeout(r, 180));
        steps[i].classList.add('active');
    }

    await new Promise(r => setTimeout(r, 280));
    overlay.classList.add('hidden');
}

let toastTimeout;
function showToast(message, isError = false) {
    const toast = document.getElementById('nexus-toast');
    const msgEl = document.getElementById('toast-message');

    msgEl.textContent = message;
    toast.className = `cyber-toast show ${isError ? 'error' : ''}`;

    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
        toast.className = 'cyber-toast';
    }, 3800);
}

function toggleAuthMode() {
    isRegisterMode = !isRegisterMode;
    const titleEl = document.getElementById('auth-heading');
    const descEl = document.getElementById('auth-desc');
    const submitBtn = document.getElementById('auth-submit-btn');
    const toggleLabel = document.getElementById('auth-toggle-label');
    const stateTag = document.getElementById('auth-state-tag');

    if (isRegisterMode) {
        titleEl.textContent = 'PROVISION NEW SECURITY VAULT';
        descEl.textContent = 'Client-side PBKDF2 will derive a unique 256-bit encryption key and master salt.';
        submitBtn.querySelector('.btn-text').textContent = 'GENERATE NEW VAULT';
        toggleLabel.textContent = 'MODE: UNLOCK EXISTING VAULT';
        stateTag.textContent = 'CORE // REGISTRATION MODE';
    } else {
        titleEl.textContent = 'IDENTITY VERIFICATION REQUIRED';
        descEl.textContent = 'Zero-knowledge cryptographic initialization. Master key never traverses the wire.';
        submitBtn.querySelector('.btn-text').textContent = 'INITIALIZE VAULT';
        toggleLabel.textContent = 'MODE: REGISTER NEW IDENTITY';
        stateTag.textContent = 'SECURE CORE // OFFLINE';
    }
}

async function handleAuthentication(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const masterPassword = document.getElementById('master-password').value;

    if (!username || !masterPassword) {
        showToast('Operator username and Master Key are required.', true);
        return;
    }

    const submitBtn = document.getElementById('auth-submit-btn');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').textContent = 'PROCESSING CRYPTO...';

    try {
        let salt;
        if (isRegisterMode) {
            salt = generateSecureSalt();
        } else {
            const saltRes = await fetch(`/api/auth/salt/${encodeURIComponent(username)}`);
            const saltData = await saltRes.json();
            salt = saltData.salt;
        }

        const { encKey, clientAuthHash } = await deriveCryptographicKeys(masterPassword, salt);

        const endpoint = isRegisterMode ? '/api/register' : '/api/login';
        const payload = isRegisterMode
            ? { username, clientAuthHash, salt }
            : { username, clientAuthHash };

        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Authentication rejected by security core.');

        currentUser = { id: data.userId, username: data.username };
        encryptionKey = encKey;

        document.getElementById('auth-form').reset();
        await playCinematicUnlockSequence();
        transitionToVaultView();

        showToast(isRegisterMode ? 'Digital Vault Core generated and unlocked.' : 'Access granted. Welcome, Operator.');
        await loadVaultCapsules();
        startInactivityDaemon();

    } catch (err) {
        showToast(err.message, true);
    } finally {
        submitBtn.disabled = false;
        submitBtn.querySelector('.btn-text').textContent = isRegisterMode ? 'GENERATE NEW VAULT' : 'INITIALIZE VAULT';
    }
}

function transitionToVaultView() {
    document.getElementById('auth-screen').classList.add('hidden-panel');
    document.getElementById('vault-screen').classList.remove('hidden-panel');
    document.getElementById('user-controls').classList.remove('hidden');

    document.getElementById('nav-username').textContent = currentUser.username.toUpperCase();
    document.getElementById('core-status-dot').className = 'status-indicator online';
    document.getElementById('core-status-text').textContent = 'CORE // ONLINE';
}

async function executeVaultLock(message = 'ENCRYPTED SESSION TERMINATED') {
    encryptionKey = null;
    currentUser = null;
    cachedVaultItems = [];
    clearInterval(inactivityTimerInterval);

    activeRevealTimers.forEach(timer => clearTimeout(timer));
    activeRevealTimers.clear();

    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (_) {}

    document.getElementById('vault-capsules-list').innerHTML = '';
    document.getElementById('vault-counter').textContent = '00';
    document.getElementById('vault-search-input').value = '';

    document.getElementById('vault-screen').classList.add('hidden-panel');
    document.getElementById('auth-screen').classList.remove('hidden-panel');
    document.getElementById('user-controls').classList.add('hidden');

    document.getElementById('core-status-dot').className = 'status-indicator';
    document.getElementById('core-status-text').textContent = 'CORE // OFFLINE';

    closeCreateModal();
    closeGeneratorModal();

    showToast(message);
}

async function loadVaultCapsules() {
    try {
        const res = await fetch('/api/vault');
        if (!res.ok) throw new Error('Failed to retrieve encrypted vault matrix.');

        cachedVaultItems = await res.json();
        renderFilteredCapsules(cachedVaultItems);
    } catch (err) {
        showToast(err.message, true);
    }
}

function renderFilteredCapsules(items) {
    const listEl = document.getElementById('vault-capsules-list');
    listEl.innerHTML = '';

    const countFormatted = items.length < 10 ? `0${items.length}` : `${items.length}`;
    document.getElementById('vault-counter').textContent = countFormatted;

    if (items.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'vault-empty-state';

        const title = document.createElement('div');
        title.className = 'empty-title';
        title.textContent = 'NO ENCRYPTED CAPSULES FOUND';

        const sub = document.createElement('div');
        sub.className = 'empty-sub';
        sub.textContent = 'Create your first secure encrypted object by clicking "+ CREATE SECRET".';

        emptyState.appendChild(title);
        emptyState.appendChild(sub);
        listEl.appendChild(emptyState);
        return;
    }

    items.forEach(item => {
        const capsule = createCapsuleDOMElement(item);
        listEl.appendChild(capsule);
    });
}

function createCapsuleDOMElement(item) {
    const row = document.createElement('div');
    row.className = 'capsule-item';
    row.setAttribute('role', 'listitem');
    row.dataset.id = item.id;

    const colId = document.createElement('div');
    colId.className = 'capsule-identifier';

    const avatar = document.createElement('div');
    avatar.className = 'capsule-avatar';
    avatar.textContent = (item.title || 'S').slice(0, 2).toUpperCase();

    const names = document.createElement('div');
    names.className = 'capsule-names';

    const title = document.createElement('span');
    title.className = 'capsule-title';
    title.textContent = item.title;

    const time = document.createElement('span');
    time.className = 'capsule-time';
    const date = new Date(item.updated_at || item.created_at);
    time.textContent = `SYNCED // ${date.toLocaleDateString()}`;

    names.appendChild(title);
    names.appendChild(time);
    colId.appendChild(avatar);
    colId.appendChild(names);

    const colUser = document.createElement('div');
    colUser.className = 'capsule-identity';
    colUser.textContent = 'ENCRYPTED';

    const colCipher = document.createElement('div');
    colCipher.className = 'capsule-cipher';

    const dots = document.createElement('span');
    dots.className = 'cipher-dots';
    dots.textContent = '••••••••••••••••';

    const badge = document.createElement('div');
    badge.className = 'cipher-badge';
    badge.textContent = 'PROTECTED';

    colCipher.appendChild(dots);
    colCipher.appendChild(badge);

    const colActions = document.createElement('div');
    colActions.className = 'capsule-actions';

    const accessBtn = document.createElement('button');
    accessBtn.type = 'button';
    accessBtn.className = 'btn btn-secondary btn-action';
    accessBtn.textContent = 'ACCESS';

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn btn-primary btn-action';
    copyBtn.textContent = 'COPY';

    const purgeBtn = document.createElement('button');
    purgeBtn.type = 'button';
    purgeBtn.className = 'btn btn-purge';
    purgeBtn.title = 'Purge capsule';
    purgeBtn.textContent = '✕';

    accessBtn.addEventListener('click', async () => {
        if (!encryptionKey) return;

        if (activeRevealTimers.has(item.id)) {
            clearTimeout(activeRevealTimers.get(item.id));
            activeRevealTimers.delete(item.id);
            dots.className = 'cipher-dots';
            dots.textContent = '••••••••••••••••';
            badge.className = 'cipher-badge';
            badge.textContent = 'PROTECTED';
            colUser.textContent = 'ENCRYPTED';
            accessBtn.textContent = 'ACCESS';
            return;
        }

        badge.textContent = 'DECRYPTING...';
        accessBtn.disabled = true;

        try {
            const decrypted = await decryptSecretPayload(item.encrypted_data, encryptionKey);
            colUser.textContent = decrypted.username;
            dots.className = 'cipher-dots revealed';
            dots.textContent = decrypted.password;
            accessBtn.textContent = 'CONCEAL';

            let countdown = 10;
            badge.className = 'cipher-badge active-reveal';
            badge.textContent = `SECRET VISIBLE • ${countdown}s`;

            const timer = setInterval(() => {
                countdown--;
                if (countdown > 0) {
                    badge.textContent = `SECRET VISIBLE • ${countdown}s`;
                } else {
                    clearInterval(timer);
                    activeRevealTimers.delete(item.id);
                    dots.className = 'cipher-dots';
                    dots.textContent = '••••••••••••••••';
                    badge.className = 'cipher-badge';
                    badge.textContent = 'PROTECTED';
                    colUser.textContent = 'ENCRYPTED';
                    accessBtn.textContent = 'ACCESS';
                }
            }, 1000);

            activeRevealTimers.set(item.id, timer);
        } catch (_) {
            showToast('Decryption error: Master key mismatch.', true);
        } finally {
            accessBtn.disabled = false;
        }
    });

    copyBtn.addEventListener('click', async () => {
        if (!encryptionKey) return;

        try {
            const decrypted = await decryptSecretPayload(item.encrypted_data, encryptionKey);
            await navigator.clipboard.writeText(decrypted.password);
            showToast(`Secret for "${item.title}" copied to clipboard.`);

            setTimeout(async () => {
                try {
                    const currentClip = await navigator.clipboard.readText();
                    if (currentClip === decrypted.password) {
                        await navigator.clipboard.writeText('');
                        showToast('Clipboard automatically wiped for security.');
                    }
                } catch (_) {}
            }, 45000);

        } catch (_) {
            showToast('Failed to copy secret.', true);
        }
    });

    purgeBtn.addEventListener('click', async () => {
        if (!confirm(`Purge encrypted capsule "${item.title}" from storage?`)) return;

        try {
            const res = await fetch(`/api/vault/${item.id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Purge failed');

            showToast(`Capsule "${item.title}" purged from storage.`);
            cachedVaultItems = cachedVaultItems.filter(i => i.id !== item.id);
            renderFilteredCapsules(cachedVaultItems);
        } catch (err) {
            showToast(err.message, true);
        }
    });

    colActions.appendChild(accessBtn);
    colActions.appendChild(copyBtn);
    colActions.appendChild(purgeBtn);

    row.appendChild(colId);
    row.appendChild(colUser);
    row.appendChild(colCipher);
    row.appendChild(colActions);

    return row;
}

function filterCapsules(query) {
    const q = query.toLowerCase().trim();
    if (!q) {
        renderFilteredCapsules(cachedVaultItems);
        return;
    }
    const filtered = cachedVaultItems.filter(item => item.title.toLowerCase().includes(q));
    renderFilteredCapsules(filtered);
}

function openCreateModal() {
    document.getElementById('create-modal').classList.remove('hidden');
    document.getElementById('capsule-title').focus();
}

function closeCreateModal() {
    document.getElementById('create-modal').classList.add('hidden');
    document.getElementById('create-secret-form').reset();
    document.getElementById('creation-pipeline').classList.add('hidden');
    resetStrengthMeter();
}

function resetStrengthMeter() {
    const segs = [1, 2, 3, 4].map(n => document.getElementById(`seg-${n}`));
    segs.forEach(s => s.className = 'strength-segment');
    document.getElementById('strength-readout').textContent = 'STRENGTH: ENTER PASSWORD';
}

function evaluatePasswordQuality(password, segs, readoutEl, defaultText = 'ENTER PASSWORD') {
    segs.forEach(s => s.className = 'strength-segment');

    if (!password || password.length === 0) {
        readoutEl.textContent = `STRENGTH: ${defaultText}`;
        return;
    }

    let score = 0;
    if (password.length >= 10) score++;
    if (password.length >= 15) score++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 1) {
        segs[0].classList.add('active-weak');
        readoutEl.textContent = 'STRENGTH: LEAST';
    } else if (score === 2) {
        segs[0].classList.add('active-fair');
        segs[1].classList.add('active-fair');
        readoutEl.textContent = 'STRENGTH: AVERAGE';
    } else if (score === 3) {
        segs[0].classList.add('active-good');
        segs[1].classList.add('active-good');
        segs[2].classList.add('active-good');
        readoutEl.textContent = 'STRENGTH: GOOD';
    } else {
        segs.forEach(s => s.classList.add('active-strong'));
        readoutEl.textContent = 'STRENGTH: BEST';
    }
}

async function handleSaveCapsule(e) {
    e.preventDefault();
    const title = document.getElementById('capsule-title').value.trim();
    const username = document.getElementById('capsule-username').value.trim();
    const password = document.getElementById('capsule-password').value;

    if (!title || !username || !password) {
        showToast('All fields required to seal capsule.', true);
        return;
    }

    const pipeline = document.getElementById('creation-pipeline');
    pipeline.classList.remove('hidden');

    const p1 = document.getElementById('pipe-1');
    const p2 = document.getElementById('pipe-2');
    const p3 = document.getElementById('pipe-3');

    p1.className = 'pipeline-step active';
    p2.className = 'pipeline-step';
    p3.className = 'pipeline-step';

    try {
        await new Promise(r => setTimeout(r, 120));
        p1.className = 'pipeline-step done';
        p2.className = 'pipeline-step active';

        const encryptedData = await encryptSecretPayload({ username, password }, encryptionKey);

        await new Promise(r => setTimeout(r, 150));
        p2.className = 'pipeline-step done';
        p3.className = 'pipeline-step active';

        const res = await fetch('/api/vault', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, encryptedData })
        });

        if (!res.ok) throw new Error('Failed to commit encrypted capsule to storage.');

        p3.className = 'pipeline-step done';
        await new Promise(r => setTimeout(r, 150));

        closeCreateModal();
        showToast(`Secret capsule "${title}" sealed and committed.`);
        await loadVaultCapsules();

    } catch (err) {
        showToast(err.message, true);
        pipeline.classList.add('hidden');
    }
}

function openGeneratorModal() {
    document.getElementById('generator-modal').classList.remove('hidden');
    refreshGeneratedSecret();
}

function closeGeneratorModal() {
    document.getElementById('generator-modal').classList.add('hidden');
}

function refreshGeneratedSecret() {
    const length = parseInt(document.getElementById('gen-length-slider').value, 10);
    const upper = document.getElementById('gen-opt-upper').checked;
    const lower = document.getElementById('gen-opt-lower').checked;
    const numbers = document.getElementById('gen-opt-numbers').checked;
    const symbols = document.getElementById('gen-opt-symbols').checked;

    const pass = generateCryptographicPassword(length, { upper, lower, numbers, symbols });
    document.getElementById('gen-output-text').textContent = pass;
    document.getElementById('gen-entropy-bits').textContent = 'OPTIMAL';
}

document.addEventListener('DOMContentLoaded', () => {
    initAmbientBackground();

    const timeEl = document.getElementById('system-time');
    function updateClock() {
        const now = new Date();
        timeEl.textContent = `TIME_STAMP // ${now.toISOString().replace('T', ' // ').slice(0, -5)} UTC`;
    }
    setInterval(updateClock, 1000);
    updateClock();

    document.getElementById('auth-form').addEventListener('submit', handleAuthentication);
    document.getElementById('auth-toggle-btn').addEventListener('click', toggleAuthMode);

    const authSegs = [1, 2, 3, 4].map(n => document.getElementById(`auth-seg-${n}`));
    const authReadout = document.getElementById('auth-strength-readout');
    document.getElementById('master-password').addEventListener('input', (e) => {
        evaluatePasswordQuality(e.target.value, authSegs, authReadout, 'ENTER MASTER KEY');
    });

    document.getElementById('toggle-master-pw').addEventListener('click', () => {
        const input = document.getElementById('master-password');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    document.getElementById('lock-vault-btn').addEventListener('click', () => {
        executeVaultLock('ENCRYPTED SESSION TERMINATED: Keys purged from memory.');
    });

    document.getElementById('vault-search-input').addEventListener('input', (e) => {
        filterCapsules(e.target.value);
    });

    document.getElementById('open-create-modal-btn').addEventListener('click', openCreateModal);
    document.getElementById('cancel-create-btn').addEventListener('click', closeCreateModal);
    document.getElementById('create-secret-form').addEventListener('submit', handleSaveCapsule);

    const modalSegs = [1, 2, 3, 4].map(n => document.getElementById(`seg-${n}`));
    const modalReadout = document.getElementById('strength-readout');
    document.getElementById('capsule-password').addEventListener('input', (e) => {
        evaluatePasswordQuality(e.target.value, modalSegs, modalReadout, 'ENTER PASSWORD');
    });

    document.getElementById('toggle-capsule-pw').addEventListener('click', () => {
        const input = document.getElementById('capsule-password');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    document.getElementById('quick-gen-btn').addEventListener('click', () => {
        const pass = generateCryptographicPassword(24, { upper: true, lower: true, numbers: true, symbols: true });
        const input = document.getElementById('capsule-password');
        input.value = pass;
        input.type = 'text';
        evaluatePasswordQuality(pass, modalSegs, modalReadout, 'ENTER PASSWORD');
        showToast('Generated strong password populated.');
    });

    document.getElementById('open-generator-modal-btn').addEventListener('click', openGeneratorModal);
    document.getElementById('close-gen-btn').addEventListener('click', closeGeneratorModal);
    document.getElementById('regen-btn').addEventListener('click', refreshGeneratedSecret);

    const lengthSlider = document.getElementById('gen-length-slider');
    lengthSlider.addEventListener('input', (e) => {
        document.getElementById('gen-length-val').textContent = `${e.target.value} CHARS`;
        refreshGeneratedSecret();
    });

    ['gen-opt-upper', 'gen-opt-lower', 'gen-opt-numbers', 'gen-opt-symbols'].forEach(id => {
        document.getElementById(id).addEventListener('change', refreshGeneratedSecret);
    });

    document.getElementById('copy-generated-btn').addEventListener('click', async () => {
        const pass = document.getElementById('gen-output-text').textContent;
        await navigator.clipboard.writeText(pass);
        showToast('Secret copied to clipboard.');
    });

    window.addEventListener('click', (e) => {
        if (e.target.id === 'create-modal') closeCreateModal();
        if (e.target.id === 'generator-modal') closeGeneratorModal();
    });

    document.addEventListener('contextmenu', (e) => e.preventDefault());

    document.addEventListener('keydown', (e) => {
        if (e.key === 'F12') {
            e.preventDefault();
            return false;
        }
        if (e.ctrlKey && (e.key === 'u' || e.key === 'U' || e.key === 's' || e.key === 'S')) {
            e.preventDefault();
            return false;
        }
        if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
            e.preventDefault();
            return false;
        }
    });
});
