(() => {
    // Supabase config 
    const SUPABASE_URL = 'https://vgcnwwivxoekjttcxzrw.supabase.co';
    const SUPABASE_ANON_KEY = 'sb_publishable_iv2ZeBm70N0X6RdrE3vcNQ_8qngA5xW';
    const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    const enc = new TextEncoder();
    const dec = new TextDecoder();

    // Utility: base64 <-> bytes
    const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const fromB64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

    // Crypto core 
    async function deriveKey(password, saltBytes) {
        const baseKey = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: saltBytes, iterations: 200000, hash: 'SHA-256' },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptVault(key, vaultObj) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plaintext = enc.encode(JSON.stringify(vaultObj));
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
        return { iv: toB64(iv), data: toB64(ciphertext) };
    }

    async function decryptVault(key, ivB64, dataB64) {
        const iv = fromB64(ivB64);
        const ciphertext = fromB64(dataB64);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return JSON.parse(dec.decode(plaintext));
    }

    // Storage (Supabase) 
    // Every read/write here deals in ciphertext only — salt, iv, and the
    // encrypted blob. Supabase never sees a password or plaintext entry.
    async function readStore() {
        const { data: sessionData } = await supabase.auth.getSession();
        const uid = sessionData.session?.user?.id;
        if (!uid) return null;
        const { data, error } = await supabase
            .from('vaults')
            .select('salt, iv, data')
            .eq('user_id', uid)
            .maybeSingle();
        if (error) { console.error(error); return null; }
        return data;
    }

    async function writeStore(obj) {
        const { data: sessionData } = await supabase.auth.getSession();
        const uid = sessionData.session?.user?.id;
        if (!uid) throw new Error('Not signed in');
        const { error } = await supabase
            .from('vaults')
            .upsert({ user_id: uid, salt: obj.salt, iv: obj.iv, data: obj.data, updated_at: new Date().toISOString() });
        if (error) throw error;
    }

    // App state 
    let sessionKey = null;   // CryptoKey, in memory only
    let currentSalt = null;  // base64 salt for this user's vault, in memory only
    let vault = null;        // { entries: [...] }
    let activeId = null;
    let clipboardTimer = null;

    // Elements 
    const screenAuth = document.getElementById('screen-auth');
    const screenSetup = document.getElementById('screen-setup');
    const screenUnlock = document.getElementById('screen-unlock');
    const app = document.getElementById('app');

    function showScreen(name) {
        screenAuth.classList.add('hidden');
        screenSetup.classList.add('hidden');
        screenUnlock.classList.add('hidden');
        app.classList.remove('active');
        if (name === 'auth') screenAuth.classList.remove('hidden');
        if (name === 'setup') screenSetup.classList.remove('hidden');
        if (name === 'unlock') screenUnlock.classList.remove('hidden');
        if (name === 'app') app.classList.add('active');
    }

    function toast(msg) {
        const t = document.getElementById('toast');
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(toast._timer);
        toast._timer = setTimeout(() => t.classList.remove('show'), 2200);
    }

    // Password show/hide toggles 
    document.querySelectorAll('[data-toggle]').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById(btn.dataset.toggle);
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.textContent = show ? 'hide' : 'show';
        });
    });

    // Dial decoration (drawn once for each dial)
    function drawTicks(gId) {
        const g = document.getElementById(gId);
        const N = 40;
        for (let i = 0; i < N; i++) {
            const angle = (i / N) * 2 * Math.PI;
            const major = i % 5 === 0;
            const rOuter = 52;
            const rInner = major ? 44 : 48;
            const x1 = 60 + rOuter * Math.sin(angle);
            const y1 = 60 - rOuter * Math.cos(angle);
            const x2 = 60 + rInner * Math.sin(angle);
            const y2 = 60 - rInner * Math.cos(angle);
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', x1); line.setAttribute('y1', y1);
            line.setAttribute('x2', x2); line.setAttribute('y2', y2);
            line.setAttribute('class', 'tick' + (major ? ' major' : ''));
            g.appendChild(line);
        }
    }
    drawTicks('ticks-setup');
    drawTicks('ticks-unlock');

    function spinDial(dialEl, cb) {
        dialEl.classList.add('spin');
        setTimeout(() => {
            dialEl.classList.remove('spin');
            if (cb) cb();
        }, 900);
    }

    // Password strength meter
    function strengthScore(pw) {
        let score = 0;
        if (pw.length >= 10) score += 25;
        if (pw.length >= 16) score += 15;
        if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 20;
        if (/\d/.test(pw)) score += 20;
        if (/[^A-Za-z0-9]/.test(pw)) score += 20;
        return Math.min(score, 100);
    }
    document.getElementById('setup-pw').addEventListener('input', (e) => {
        const s = strengthScore(e.target.value);
        const fill = document.getElementById('strength-fill');
        fill.style.width = s + '%';
        fill.style.background = s < 40 ? 'var(--danger)' : s < 75 ? 'var(--brass)' : 'var(--good)';
    });

    // Auth (Supabase)
    document.getElementById('btn-signup').addEventListener('click', async () => {
        const email = document.getElementById('auth-email').value.trim();
        const password = document.getElementById('auth-password').value;
        const errEl = document.getElementById('auth-error');
        errEl.textContent = '';
        const { error } = await supabase.auth.signUp({ email, password });
        if (error) { errEl.textContent = error.message; return; }
        toast('Account created. Check your email if confirmation is required.');
        await afterAuthChange();
    });

    document.getElementById('btn-signin').addEventListener('click', async () => {
        const email = document.getElementById('auth-email').value.trim();
        const password = document.getElementById('auth-password').value;
        const errEl = document.getElementById('auth-error');
        errEl.textContent = '';
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) { errEl.textContent = error.message; return; }
        await afterAuthChange();
    });

    document.getElementById('btn-signout').addEventListener('click', async () => {
        await supabase.auth.signOut();
        sessionKey = null;
        vault = null;
        activeId = null;
        showScreen('auth');
    });

    async function afterAuthChange() {
        const store = await readStore();
        if (!store) {
            showScreen('setup');
        } else {
            showScreen('unlock');
        }
    }

    // Boot 
    async function boot() {
        const { data: sessionData } = await supabase.auth.getSession();
        if (!sessionData.session) {
            showScreen('auth');
            return;
        }
        await afterAuthChange();
    }

    // Setup flow 
    document.getElementById('btn-create-vault').addEventListener('click', async () => {
        const pw = document.getElementById('setup-pw').value;
        const pw2 = document.getElementById('setup-pw2').value;
        const errEl = document.getElementById('setup-error');
        errEl.textContent = '';

        if (pw.length < 10) { errEl.textContent = 'Use at least 10 characters.'; return; }
        if (pw !== pw2) { errEl.textContent = 'Passwords do not match.'; return; }

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKey(pw, salt);
        const emptyVault = { entries: [] };
        const encrypted = await encryptVault(key, emptyVault);

        await writeStore({ salt: toB64(salt), iv: encrypted.iv, data: encrypted.data });

        sessionKey = key;
        currentSalt = toB64(salt);
        vault = emptyVault;

        spinDial(document.getElementById('dial-setup'), () => {
            enterApp();
        });
    });

    // Unlock flow 
    document.getElementById('btn-unlock').addEventListener('click', async () => {
        const pw = document.getElementById('unlock-pw').value;
        const errEl = document.getElementById('unlock-error');
        errEl.textContent = '';
        const store = await readStore();
        if (!store) { showScreen('setup'); return; }

        try {
            const salt = fromB64(store.salt);
            const key = await deriveKey(pw, salt);
            const decrypted = await decryptVault(key, store.iv, store.data);
            sessionKey = key;
            currentSalt = store.salt;
            vault = decrypted;
            document.getElementById('unlock-pw').value = '';
            spinDial(document.getElementById('dial-unlock'), () => enterApp());
        } catch (e) {
            errEl.textContent = 'Incorrect password.';
        }
    });
    document.getElementById('unlock-pw').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('btn-unlock').click();
    });
    document.getElementById('setup-pw2').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('btn-create-vault').click();
    });

    document.getElementById('link-reset').addEventListener('click', async (e) => {
        e.preventDefault();
        if (confirm('This permanently deletes your vault row in the database. Continue?')) {
            const { data: sessionData } = await supabase.auth.getSession();
            const uid = sessionData.session?.user?.id;
            if (uid) await supabase.from('vaults').delete().eq('user_id', uid);
            boot();
        }
    });

    document.getElementById('link-restore').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('restore-file').click();
    });
    document.getElementById('restore-file').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
            const text = await file.text();
            const parsed = JSON.parse(text);
            if (!parsed.salt || !parsed.iv || !parsed.data) throw new Error('bad file');
            await writeStore(parsed);
            toast('Backup restored. Enter your master password.');
            boot();
        } catch {
            alert('That file does not look like a valid Ledger backup.');
        }
    });

    // Persist vault (re-encrypt on every change, save to Supabase)
    async function persist() {
        const encrypted = await encryptVault(sessionKey, vault);
        await writeStore({ salt: currentSalt, iv: encrypted.iv, data: encrypted.data });
    }

    // Enter app / render 
    function enterApp() {
        showScreen('app');
        renderList();
        showEmptyDetail();
    }

    function renderList(filter = '') {
        const list = document.getElementById('entry-list');
        list.innerHTML = '';
        const items = vault.entries
            .map((e, idx) => ({ e, idx }))
            .filter(({ e }) => (e.site + e.username).toLowerCase().includes(filter.toLowerCase()));

        if (items.length === 0) {
            list.innerHTML = `<div class="empty-list">No entries yet. Use "+ New entry" to add your first credential.</div>`;
            return;
        }

        items.forEach(({ e, idx }) => {
            const row = document.createElement('div');
            row.className = 'entry-row' + (e.id === activeId ? ' active' : '');
            row.innerHTML = `
        <span class="entry-num">${String(idx + 1).padStart(2, '0')}</span>
        <div class="entry-meta">
          <div class="site">${escapeHtml(e.site || 'Untitled')}</div>
          <div class="user">${escapeHtml(e.username || '')}</div>
        </div>`;
            row.addEventListener('click', () => selectEntry(e.id));
            list.appendChild(row);
        });
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    function showEmptyDetail() {
        activeId = null;
        document.getElementById('main-empty').classList.remove('hidden');
        document.getElementById('main-detail').classList.add('hidden');
    }

    function selectEntry(id) {
        activeId = id;
        const entry = vault.entries.find(e => e.id === id);
        document.getElementById('main-empty').classList.add('hidden');
        document.getElementById('main-detail').classList.remove('hidden');
        document.getElementById('detail-title').textContent = entry.site || 'Untitled entry';
        document.getElementById('f-site').value = entry.site || '';
        document.getElementById('f-user').value = entry.username || '';
        document.getElementById('f-pass').value = entry.password || '';
        document.getElementById('f-notes').value = entry.notes || '';
        renderList(document.getElementById('search').value);
    }

    document.getElementById('btn-new-entry').addEventListener('click', () => {
        const id = crypto.randomUUID();
        vault.entries.unshift({ id, site: '', username: '', password: '', notes: '', updated: Date.now() });
        selectEntry(id);
        document.getElementById('f-site').focus();
    });

    document.getElementById('btn-save-entry').addEventListener('click', async () => {
        if (!activeId) return;
        const entry = vault.entries.find(e => e.id === activeId);
        entry.site = document.getElementById('f-site').value.trim();
        entry.username = document.getElementById('f-user').value.trim();
        entry.password = document.getElementById('f-pass').value;
        entry.notes = document.getElementById('f-notes').value;
        entry.updated = Date.now();
        await persist();
        document.getElementById('detail-title').textContent = entry.site || 'Untitled entry';
        renderList(document.getElementById('search').value);
        toast('Entry saved and encrypted.');
    });

    document.getElementById('btn-delete-entry').addEventListener('click', async () => {
        if (!activeId) return;
        if (!confirm('Delete this entry permanently?')) return;
        vault.entries = vault.entries.filter(e => e.id !== activeId);
        await persist();
        showEmptyDetail();
        renderList(document.getElementById('search').value);
        toast('Entry deleted.');
    });

    document.getElementById('search').addEventListener('input', (e) => renderList(e.target.value));

    // Copy to clipboard with auto-clear
    document.getElementById('btn-copy-pass').addEventListener('click', async () => {
        const val = document.getElementById('f-pass').value;
        if (!val) return;
        await navigator.clipboard.writeText(val);
        toast('Password copied — clears in 20s');
        clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(async () => {
            const current = await navigator.clipboard.readText().catch(() => null);
            if (current === val) await navigator.clipboard.writeText('');
        }, 20000);
    });

    // Password generator
    const genLen = document.getElementById('gen-len');
    genLen.addEventListener('input', () => {
        document.getElementById('gen-len-label').textContent = genLen.value;
    });
    document.getElementById('btn-generate').addEventListener('click', () => {
        const len = parseInt(genLen.value, 10);
        const useUpper = document.getElementById('gen-upper').checked;
        const useLower = document.getElementById('gen-lower').checked;
        const useDigits = document.getElementById('gen-digits').checked;
        const useSymbols = document.getElementById('gen-symbols').checked;

        let charset = '';
        if (useUpper) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        if (useLower) charset += 'abcdefghijkmnpqrstuvwxyz';
        if (useDigits) charset += '23456789';
        if (useSymbols) charset += '!@#$%^&*()-_=+[]{}';

        if (!charset) { toast('Pick at least one character set'); return; }

        const bytes = crypto.getRandomValues(new Uint32Array(len));
        let out = '';
        for (let i = 0; i < len; i++) out += charset[bytes[i] % charset.length];

        document.getElementById('f-pass').value = out;
        document.getElementById('f-pass').type = 'text';
    });

    // Lock / Export 
    document.getElementById('btn-lock').addEventListener('click', () => {
        sessionKey = null;
        vault = null;
        activeId = null;
        document.getElementById('unlock-pw').value = '';
        showScreen('unlock');
    });

    document.getElementById('btn-export').addEventListener('click', async () => {
        const store = await readStore();
        const blob = new Blob([JSON.stringify(store, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ledger-backup.json';
        a.click();
        URL.revokeObjectURL(url);
        toast('Encrypted backup downloaded.');
    });

    // Auto-lock on tab hidden after delay 
    let hiddenTimer = null;
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && app.classList.contains('active')) {
            hiddenTimer = setTimeout(() => document.getElementById('btn-lock').click(), 5 * 60 * 1000);
        } else {
            clearTimeout(hiddenTimer);
        }
    });

    boot();
})();