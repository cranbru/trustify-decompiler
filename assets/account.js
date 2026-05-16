/**
 * Account Management for Trustify
 * Handles user identity, scan history, and client-side persistence
 */
(function() {
    const STORAGE_KEY_USER = 'trustify_user';
    const STORAGE_KEY_HISTORY = 'trustify_history';
    const STORAGE_KEY_GEMINI_API_KEY = 'trustify_gemini_api_key';
    const STORAGE_KEY_VIRUSTOTAL_API_KEY = 'trustify_virustotal_api_key';

    const accountManager = {
        user: null,
        history: [],

        init() {
            this.loadData();
            this.setupEventListeners();
            this.checkFirstTimeUser();
            this.renderGeminiKeyState();
            this.renderVirusTotalKeyState();
            this.renderHistory();
        },

        loadData() {
            try {
                const userData = localStorage.getItem(STORAGE_KEY_USER);
                this.user = userData ? JSON.parse(userData) : null;

                const historyData = localStorage.getItem(STORAGE_KEY_HISTORY);
                this.history = historyData ? JSON.parse(historyData) : [];
            } catch (e) {
                console.error('Error loading account data:', e);
                this.user = null;
                this.history = [];
            }
        },

        saveUser(name) {
            if (!name || name.trim().length === 0) return false;
            this.user = { name: name.trim(), createdAt: new Date().toISOString() };
            try {
                localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(this.user));
                this.updateUI();
                return true;
            } catch (e) {
                alert('Storage limit reached. Could not save user name.');
                return false;
            }
        },

        getGeminiApiKey() {
            try {
                return localStorage.getItem(STORAGE_KEY_GEMINI_API_KEY) || '';
            } catch (e) {
                return '';
            }
        },

        getVirusTotalApiKey() {
            try {
                return localStorage.getItem(STORAGE_KEY_VIRUSTOTAL_API_KEY) || '';
            } catch (e) {
                return '';
            }
        },

        saveGeminiApiKey(apiKey) {
            const key = apiKey ? apiKey.trim() : '';
            try {
                if (key) {
                    localStorage.setItem(STORAGE_KEY_GEMINI_API_KEY, key);
                } else {
                    localStorage.removeItem(STORAGE_KEY_GEMINI_API_KEY);
                }
                this.renderGeminiKeyState();
                window.dispatchEvent(new CustomEvent('trustify:gemini-key-updated'));
                this.updateVisibleApiKeyReminder();
                return true;
            } catch (e) {
                alert('Could not save Gemini API key in this browser.');
                return false;
            }
        },

        saveVirusTotalApiKey(apiKey) {
            const key = apiKey ? apiKey.trim() : '';
            try {
                if (key) {
                    localStorage.setItem(STORAGE_KEY_VIRUSTOTAL_API_KEY, key);
                } else {
                    localStorage.removeItem(STORAGE_KEY_VIRUSTOTAL_API_KEY);
                }
                this.renderVirusTotalKeyState();
                window.dispatchEvent(new CustomEvent('trustify:virustotal-key-updated'));
                this.updateVisibleApiKeyReminder();
                return true;
            } catch (e) {
                alert('Could not save VirusTotal API key in this browser.');
                return false;
            }
        },

        addScanToHistory(appData) {
            const securitySummary = appData && appData.securitySummary ? appData.securitySummary : null;
            const scanEntry = {
                id: Date.now(),
                timestamp: new Date().toISOString(),
                name: appData.appLabel || 'Unknown App',
                packageName: appData.packageName || 'unknown.package',
                status: 'Completed',
                security: securitySummary
            };
            
            this.history.unshift(scanEntry); // Add to beginning (chronological)
            
            try {
                localStorage.setItem(STORAGE_KEY_HISTORY, JSON.stringify(this.history));
                this.renderHistory();
            } catch (e) {
                console.warn('History storage limit reached, removing oldest entries.');
                this.history.pop();
                localStorage.setItem(STORAGE_KEY_HISTORY, JSON.stringify(this.history));
            }
        },

        clearHistory() {
            this.history = [];
            localStorage.removeItem(STORAGE_KEY_HISTORY);
            this.renderHistory();
        },

        deleteAccount() {
            if (confirm('Are you sure you want to delete your account and all scan history? This action cannot be undone.')) {
                localStorage.removeItem(STORAGE_KEY_USER);
                localStorage.removeItem(STORAGE_KEY_HISTORY);
                localStorage.removeItem(STORAGE_KEY_GEMINI_API_KEY);
                localStorage.removeItem(STORAGE_KEY_VIRUSTOTAL_API_KEY);
                window.location.reload();
            }
        },

        checkFirstTimeUser() {
            if (!this.user) {
                document.getElementById('user-setup-modal').style.display = 'flex';
            } else {
                this.updateUI();
            }
        },

        updateUI() {
            const userNameElements = document.querySelectorAll('.display-user-name');
            userNameElements.forEach(el => el.textContent = this.user ? this.user.name : 'Guest');
            this.renderGeminiKeyState();
            this.renderVirusTotalKeyState();
        },

        renderGeminiKeyState() {
            const keyInput = document.getElementById('gemini-api-key-input');
            const keyStatus = document.getElementById('gemini-key-status');
            const hasKey = !!this.getGeminiApiKey();
            if (keyInput) {
                keyInput.value = '';
                keyInput.placeholder = hasKey ? 'Saved locally' : 'Optional API key';
            }
            if (keyStatus) {
                keyStatus.textContent = hasKey
                    ? 'Gemini key saved locally. Save an empty value to remove it.'
                    : 'Used only in this browser for the explainable assistant.';
            }
        },

        renderVirusTotalKeyState() {
            const keyInput = document.getElementById('virustotal-api-key-input');
            const keyStatus = document.getElementById('virustotal-key-status');
            const hasKey = !!this.getVirusTotalApiKey();
            if (keyInput) {
                keyInput.value = '';
                keyInput.placeholder = hasKey ? 'Saved locally' : 'Optional API key';
            }
            if (keyStatus) {
                keyStatus.textContent = hasKey
                    ? 'VirusTotal key saved locally. Save an empty value to remove it.'
                    : 'Used only for SHA-256 hash lookups. APK files are not uploaded.';
            }
        },

        getMissingApiKeys() {
            const missing = [];
            if (!this.getVirusTotalApiKey()) missing.push('VirusTotal');
            if (!this.getGeminiApiKey()) missing.push('Gemini');
            return missing;
        },

        showApiKeySetupModal() {
            const modal = document.getElementById('api-key-setup-modal');
            if (modal) modal.style.display = 'flex';
        },

        hideApiKeySetupModal() {
            const modal = document.getElementById('api-key-setup-modal');
            if (modal) modal.style.display = 'none';
        },

        openAccountPanel() {
            const accountPanel = document.getElementById('account-panel');
            if (accountPanel) accountPanel.classList.add('active');
        },

        showApiKeyReminder() {
            const missing = this.getMissingApiKeys();
            const reminder = document.getElementById('api-key-reminder');
            const message = document.getElementById('api-key-reminder-message');
            if (!reminder || missing.length === 0) return;
            if (message) {
                const label = missing.length === 2 ? 'VirusTotal and Gemini API keys' : missing[0] + ' API key';
                message.textContent = 'Add your ' + label + ' to get hash reputation and assistant support for this APK.';
            }
            reminder.hidden = false;
        },

        hideApiKeyReminder() {
            const reminder = document.getElementById('api-key-reminder');
            if (reminder) reminder.hidden = true;
        },

        updateVisibleApiKeyReminder() {
            const reminder = document.getElementById('api-key-reminder');
            if (!reminder || reminder.hidden) return;
            if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
            else this.showApiKeyReminder();
        },

        saveSetupApiKeys() {
            const geminiInput = document.getElementById('setup-gemini-api-key-input');
            const virusTotalInput = document.getElementById('setup-virustotal-api-key-input');
            const geminiValue = geminiInput ? geminiInput.value : '';
            const virusTotalValue = virusTotalInput ? virusTotalInput.value : '';
            let saved = true;

            if (geminiValue.trim()) saved = this.saveGeminiApiKey(geminiValue) && saved;
            if (virusTotalValue.trim()) saved = this.saveVirusTotalApiKey(virusTotalValue) && saved;

            if (saved) {
                if (geminiInput) geminiInput.value = '';
                if (virusTotalInput) virusTotalInput.value = '';
                this.hideApiKeySetupModal();
                if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
            }
        },

        renderHistory(filter = '') {
            const historyContainer = document.getElementById('scan-history-list');
            if (!historyContainer) return;

            const filteredHistory = this.history.filter(item => 
                item.name.toLowerCase().includes(filter.toLowerCase()) || 
                item.packageName.toLowerCase().includes(filter.toLowerCase())
            );

            if (filteredHistory.length === 0) {
                historyContainer.innerHTML = '<div class="empty-history">No scan history found.</div>';
                return;
            }

            const riskPill = (security) => {
                if (!security || !security.level) return '';
                const level = security.level.toLowerCase();
                const score = typeof security.score === 'number' ? security.score : '';
                return `<span class="security-pill security-pill--${level}">${security.level}${score !== '' ? ` · ${score}` : ''}</span>`;
            };

            historyContainer.innerHTML = filteredHistory.map(item => `
                <div class="history-item">
                    <div class="history-item__info">
                        <span class="history-item__name">${item.name}</span>
                        <span class="history-item__package">${item.packageName}</span>
                    </div>
                    <div class="history-item__meta">
                        <span class="history-item__date">${new Date(item.timestamp).toLocaleDateString()}</span>
                        ${riskPill(item.security)}
                        <span class="history-item__status status-${item.status.toLowerCase()}">${item.status}</span>
                    </div>
                </div>
            `).join('');
        },

        setupEventListeners() {
            // Modal submit
            const setupForm = document.getElementById('user-setup-form');
            if (setupForm) {
                setupForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    const nameInput = document.getElementById('user-name-input');
                    if (this.saveUser(nameInput.value)) {
                        document.getElementById('user-setup-modal').style.display = 'none';
                        if (this.getMissingApiKeys().length > 0) this.showApiKeySetupModal();
                    }
                });
            }

            const apiKeySetupForm = document.getElementById('api-key-setup-form');
            if (apiKeySetupForm) {
                apiKeySetupForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.saveSetupApiKeys();
                });
            }

            const skipApiKeySetupBtn = document.getElementById('skip-api-key-setup-btn');
            if (skipApiKeySetupBtn) {
                skipApiKeySetupBtn.addEventListener('click', () => this.hideApiKeySetupModal());
            }

            // Account toggle
            const accountBtn = document.getElementById('account-toggle');
            const accountPanel = document.getElementById('account-panel');
            if (accountBtn && accountPanel) {
                accountBtn.addEventListener('click', () => {
                    accountPanel.classList.toggle('active');
                });
            }

            const fileInput = document.getElementById('file-input');
            if (fileInput) {
                fileInput.addEventListener('change', () => this.showApiKeyReminder());
            }

            const fileSection = document.getElementById('select-files-section');
            if (fileSection) {
                fileSection.addEventListener('drop', () => this.showApiKeyReminder());
            }

            const reminderAction = document.getElementById('api-key-reminder-action');
            if (reminderAction) {
                reminderAction.addEventListener('click', () => {
                    this.openAccountPanel();
                    this.hideApiKeySetupModal();
                });
            }

            const reminderClose = document.getElementById('api-key-reminder-close');
            if (reminderClose) {
                reminderClose.addEventListener('click', () => this.hideApiKeyReminder());
            }

            // Close panel
            const closePanelBtn = document.getElementById('close-account-panel');
            if (closePanelBtn) {
                closePanelBtn.addEventListener('click', () => {
                    accountPanel.classList.remove('active');
                });
            }

            // History search
            const searchInput = document.getElementById('history-search');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => {
                    this.renderHistory(e.target.value);
                });
            }

            // Controls
            const clearHistoryBtn = document.getElementById('clear-history-btn');
            if (clearHistoryBtn) {
                clearHistoryBtn.addEventListener('click', () => this.clearHistory());
            }

            const deleteAccountBtn = document.getElementById('delete-account-btn');
            if (deleteAccountBtn) {
                deleteAccountBtn.addEventListener('click', () => this.deleteAccount());
            }

            const saveGeminiKeyBtn = document.getElementById('save-gemini-key-btn');
            const geminiKeyInput = document.getElementById('gemini-api-key-input');
            if (saveGeminiKeyBtn && geminiKeyInput) {
                saveGeminiKeyBtn.addEventListener('click', () => {
                    this.saveGeminiApiKey(geminiKeyInput.value);
                    if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
                });
                geminiKeyInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.saveGeminiApiKey(geminiKeyInput.value);
                        if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
                    }
                });
            }

            const saveVirusTotalKeyBtn = document.getElementById('save-virustotal-key-btn');
            const virusTotalKeyInput = document.getElementById('virustotal-api-key-input');
            if (saveVirusTotalKeyBtn && virusTotalKeyInput) {
                saveVirusTotalKeyBtn.addEventListener('click', () => {
                    this.saveVirusTotalApiKey(virusTotalKeyInput.value);
                    if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
                });
                virusTotalKeyInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.saveVirusTotalApiKey(virusTotalKeyInput.value);
                        if (this.getMissingApiKeys().length === 0) this.hideApiKeyReminder();
                    }
                });
            }

            const editNameBtn = document.getElementById('edit-name-btn');
            if (editNameBtn) {
                editNameBtn.addEventListener('click', () => {
                    const newName = prompt('Enter new display name:', this.user ? this.user.name : '');
                    if (newName) this.saveUser(newName);
                });
            }
        }
    };

    window.AccountManager = accountManager;
    document.addEventListener('DOMContentLoaded', () => accountManager.init());
})();
