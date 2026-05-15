/**
 * Account Management for Trustify
 * Handles user identity, scan history, and client-side persistence
 */
(function() {
    const STORAGE_KEY_USER = 'trustify_user';
    const STORAGE_KEY_HISTORY = 'trustify_history';

    const accountManager = {
        user: null,
        history: [],

        init() {
            this.loadData();
            this.setupEventListeners();
            this.checkFirstTimeUser();
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
                    }
                });
            }

            // Account toggle
            const accountBtn = document.getElementById('account-toggle');
            const accountPanel = document.getElementById('account-panel');
            if (accountBtn && accountPanel) {
                accountBtn.addEventListener('click', () => {
                    accountPanel.classList.toggle('active');
                });
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
