// Global variables for modal
let pendingBlockData = null;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide icons
    lucide.createIcons();

    const emailList = document.getElementById('email-list');
    const urgentSection = document.getElementById('urgent-section');
    const urgentContainer = document.getElementById('urgent-container');
    const threatCountSpan = document.getElementById('threat-count');
    const blockedList = document.getElementById('blocked-list');
    const loginLogsBody = document.getElementById('login-logs-body');
    const bankTransactionsBody = document.getElementById('bank-transactions-body');
    const selectedAccountSpan = document.getElementById('selected-account-id');

    let globalHighRiskEmails = [];
    let globalHighRiskLogs = [];
    let globalHighRiskTxns = [];

    function renderUrgentAlerts(containerId, sectionId, filterTypes = ['email', 'network', 'bank']) {
        const container = document.getElementById(containerId);
        const section = document.getElementById(sectionId);
        if (!container || !section) return;

        container.innerHTML = '';

        let allItems = [];
        if (filterTypes.includes('email')) allItems = [...allItems, ...globalHighRiskEmails.map(e => ({ ...e, type: 'email' }))];
        if (filterTypes.includes('network')) allItems = [...allItems, ...globalHighRiskLogs.map(l => ({ ...l, type: 'network' }))];
        if (filterTypes.includes('bank')) allItems = [...allItems, ...globalHighRiskTxns.map(t => ({ ...t, type: 'bank' }))];

        allItems.forEach(item => {
            const card = document.createElement('div');
            card.className = 'urgent-card';

            if (item.type === 'email') {
                const autoBlockedBadge = item.auto_blocked ? '<span class="auto-blocked-badge">AUTO-BLOCKED</span>' : '';
                const blockButton = item.risk_score >= 90
                    ? `<button class="action-btn" disabled>Auto-Blocked</button>`
                    : `<button class="action-btn" onclick="handleBlockClick('${item.sender}', '${item.subject}', ${item.risk_score}, '${item.id}')">Block Sender</button>`;

                card.innerHTML = `
                    <div class="risk-score-badge">
                        ${item.risk_score}%
                        <span>RISK</span>
                    </div>
                    <div class="alert-content">
                        <h4>${item.subject} ${autoBlockedBadge}</h4>
                        <p class="text-sm text-gray-600">From: ${item.sender}</p>
                        <div class="reason-box">
                            <i data-lucide="alert-octagon" style="width:14px; height:14px; vertical-align:middle;"></i> 
                            ${item.risk_reason}
                        </div>
                    </div>
                    <div>
                        ${blockButton}
                    </div>
                `;
            } else if (item.type === 'bank') {
                card.innerHTML = `
                    <div class="risk-score-badge" style="background: var(--color-critical); color: white;">
                        ${item.risk_score}%
                        <span>FRAUD</span>
                    </div>
                    <div class="alert-content">
                        <h4>Bank Fraud Detected: ${item.account_id}</h4>
                        <p class="text-sm text-gray-600">Merchant: <strong>${item.merchant}</strong> | Amount: <strong>$${item.amount}</strong></p>
                        <div class="reason-box" style="background: #fff5f5; border-color: #feb2b2;">
                            <i data-lucide="landmark" style="width:14px; height:14px; vertical-align:middle; color: #e53e3e;"></i> 
                            ${item.reason}
                        </div>
                    </div>
                    <div>
                        <button class="action-btn" onclick="showBankView(event)">View Details</button>
                    </div>
                `;
            } else {
                card.innerHTML = `
                    <div class="risk-score-badge" style="background: var(--color-critical); color: white;">
                        ${item.risk_score}%
                        <span>THREAT</span>
                    </div>
                    <div class="alert-content">
                        <h4>Urgent Network Alert: ${item.category}</h4>
                        <p class="text-sm text-gray-600">Source IP: <span style="font-family: monospace;">${item.ip}</span></p>
                        <div class="reason-box" style="background: #fff5f5; border-color: #feb2b2;">
                            <i data-lucide="zap" style="width:14px; height:14px; vertical-align:middle; color: #e53e3e;"></i> 
                            Active ${item.category} detected over ${item.service.toUpperCase()}/${item.proto.toUpperCase()}. Action recommended.
                        </div>
                    </div>
                    <div>
                        <button class="action-btn" onclick="showLoginLogs(event)">Investigate</button>
                    </div>
                `;
            }
            container.appendChild(card);
        });

        section.style.display = allItems.length > 0 ? 'block' : 'none';
        lucide.createIcons();
    }

    function refreshAllAlerts() {
        // Cumulative on Dashboard
        renderUrgentAlerts('urgent-container', 'urgent-section', ['email', 'network', 'bank']);
        // Specific on tabs
        renderUrgentAlerts('urgent-container-login', 'urgent-section-login', ['network']);
        renderUrgentAlerts('urgent-container-bank', 'urgent-section-bank', ['bank']);
    }

    function fetchLoginLogs() {
        console.log("Fetching login logs...");
        fetch('/api/login-logs')
            .then(response => response.json())
            .then(data => {
                if (data.logs) {
                    globalHighRiskLogs = data.logs.filter(l => l.risk_score >= 80);
                    renderLoginLogs(data.logs);
                    refreshAllAlerts();
                }
            })
            .catch(err => console.error('Error fetching login logs:', err));
    }

    function renderLoginLogs(logs) {
        if (!loginLogsBody) return;
        loginLogsBody.innerHTML = '';

        logs.forEach(log => {
            const row = document.createElement('tr');

            let badgeClass = 'normal';
            if (log.category === 'Brute Force' || log.category === 'DDoS' || log.category === 'DDoS Attack' || log.category === 'Ransomware Entry') badgeClass = 'threat';
            if (log.category === 'Reconnaissance') badgeClass = 'warning';

            row.innerHTML = `
                <td>${log.timestamp}</td>
                <td style="font-family: monospace;">${log.ip}</td>
                <td>${log.service.toUpperCase()} / ${log.proto.toUpperCase()}</td>
                <td><span class="state-pill">${log.state}</span></td>
                <td><span class="risk-badge ${badgeClass}">${log.category}</span></td>
                <td style="font-weight:bold; color: ${log.risk_score > 50 ? 'var(--color-critical)' : 'inherit'}">${log.risk_score}</td>
            `;
            loginLogsBody.appendChild(row);
        });
    }

    function fetchBankTransactions() {
        fetch('/api/bank-transactions')
            .then(response => response.json())
            .then(data => {
                if (data.transactions) {
                    globalHighRiskTxns = data.transactions.filter(t => t.is_fraud);
                    renderBankTransactions(data.transactions);
                    if (selectedAccountSpan) selectedAccountSpan.innerText = data.account_id;
                    refreshAllAlerts();
                }
            })
            .catch(err => console.error('Error fetching bank txns:', err));
    }

    function renderBankTransactions(txns) {
        if (!bankTransactionsBody) return;
        bankTransactionsBody.innerHTML = '';

        txns.forEach(tx => {
            const row = document.createElement('tr');
            const riskClass = tx.is_fraud ? 'threat' : 'normal';

            row.innerHTML = `
                <td>${tx.date}</td>
                <td>${tx.merchant}</td>
                <td>${tx.type}</td>
                <td><strong>$${tx.amount}</strong></td>
                <td>${tx.location}</td>
                <td><span class="risk-badge ${riskClass}">${tx.is_fraud ? 'Fraudulent' : 'Legitimate'}</span></td>
                <td style="font-weight:bold; color: ${tx.is_fraud ? 'var(--color-critical)' : 'inherit'}">${tx.risk_score}</td>
            `;
            bankTransactionsBody.appendChild(row);
        });
    }

    function fetchEmails() {
        fetch('/api/emails')
            .then(response => response.json())
            .then(data => {
                if (data.emails) {
                    globalHighRiskEmails = data.emails.filter(e => e.risk_score >= 65);
                    renderEmails(data.emails);
                    refreshAllAlerts();
                }
                updateStats(data.stats, data.emails || []);
            })
            .catch(err => console.error('Error fetching data:', err));
    }

    function fetchBlockedSenders() {
        fetch('/api/blocked')
            .then(response => response.json())
            .then(data => {
                renderBlockedSenders(data.blocked_senders);
            })
            .catch(err => console.error('Error fetching blocked senders:', err));
    }

    function renderEmails(emails) {
        emailList.innerHTML = '';

        emails.forEach(email => {
            // Render all in the feed
            const item = document.createElement('div');
            item.className = 'email-item';

            let riskClass = 'risk-safe';
            if (email.risk_score > 50) riskClass = 'risk-high';
            if (email.risk_score > 75) riskClass = 'risk-critical';

            const blockBtn = (email.risk_score >= 50 && email.risk_score < 90)
                ? `<button class="btn-block-small" onclick="handleBlockClick('${email.sender}', '${email.subject}', ${email.risk_score}, '${email.id}')">Block</button>`
                : '';

            item.innerHTML = `
                <div class="risk-indicator ${riskClass}">
                    ${email.risk_score}%
                </div>
                <div class="email-main">
                    <h5>${email.subject}</h5>
                    <p>${email.sender}</p>
                </div>
                <div class="email-category">
                    <span class="badge">${email.category}</span>
                    ${blockBtn}
                </div>
                <div class="email-time">
                    ${email.timestamp}
                </div>
            `;
            emailList.appendChild(item);
        });

        lucide.createIcons();
    }

    function renderBlockedSenders(blockedSenders) {
        if (!blockedSenders || blockedSenders.length === 0) {
            blockedList.innerHTML = '<div class="empty-state">No blocked senders yet.</div>';
            return;
        }

        blockedList.innerHTML = '';
        blockedSenders.forEach(blocked => {
            const item = document.createElement('div');
            item.className = 'blocked-item';

            const blockedDate = new Date(blocked.blocked_at).toLocaleString();
            const autoLabel = blocked.auto_blocked ? '<span class="auto-label">AUTO</span>' : '<span class="manual-label">MANUAL</span>';

            item.innerHTML = `
                <div class="blocked-info">
                    <h5>${blocked.email} ${autoLabel}</h5>
                    <p class="blocked-subject">Subject: ${blocked.email_subject}</p>
                    <p class="blocked-reason">${blocked.reason}</p>
                    <p class="blocked-date">Blocked: ${blockedDate}</p>
                </div>
                <div class="blocked-actions">
                    <button class="btn-unblock" onclick="unblockSender('${blocked.email}')">Unblock</button>
                </div>
            `;
            blockedList.appendChild(item);
        });

        lucide.createIcons();
    }

    function updateStats(stats, emails) {
        // Count actual high risk for the UI badge
        const highRiskCount = emails.filter(e => e.risk_score >= 70).length;
        threatCountSpan.innerText = stats.threats_blocked || 0;

        const statusHeader = document.querySelector('.status-text h2');
        const statusIcon = document.querySelector('.status-icon-large');

        if (highRiskCount > 0) {
            statusHeader.innerText = 'Threats Detected';
            statusHeader.style.color = 'var(--color-critical)';
            statusIcon.className = 'status-icon-large'; // reset
            statusIcon.style.backgroundColor = '#fef2f2';
            statusIcon.style.color = 'var(--color-critical)';
            statusIcon.innerHTML = '<i data-lucide="shield-alert"></i>';
        } else {
            statusHeader.innerText = 'System Protected';
            statusHeader.style.color = 'var(--color-safe)';
            statusIcon.className = 'status-icon-large'; // reset
            statusIcon.style.backgroundColor = '#ecfdf5';
            statusIcon.style.color = 'var(--color-safe)';
            statusIcon.innerHTML = '<i data-lucide="check-circle-2"></i>';
        }
        lucide.createIcons();
    }

    function fetchProfile() {
        fetch('/api/profile')
            .then(response => response.json())
            .then(data => {
                if (data.name) {
                    document.getElementById('user-name').innerText = data.name;
                    document.getElementById('user-email').innerText = data.email;

                    const avatarElement = document.getElementById('user-avatar');
                    if (data.picture) {
                        avatarElement.innerHTML = `<img src="${data.picture}" alt="${data.name}">`;
                    } else {
                        avatarElement.innerText = data.name.charAt(0).toUpperCase();
                    }
                }
            })
            .catch(err => console.error('Error fetching profile:', err));
    }

    // Initial Load
    fetchEmails();
    fetchBlockedSenders();
    fetchLoginLogs();
    fetchBankTransactions();
    fetchProfile();

    // Poll every 5 seconds
    setInterval(fetchEmails, 5000);
    setInterval(fetchBlockedSenders, 10000);
    setInterval(fetchLoginLogs, 6000);
    setInterval(fetchBankTransactions, 8000);

    // Make functions globally available
    window.fetchEmails = fetchEmails;
    window.fetchBlockedSenders = fetchBlockedSenders;
    window.fetchLoginLogs = fetchLoginLogs;
    window.fetchBankTransactions = fetchBankTransactions;
});

function showBankView(event) {
    if (event) event.preventDefault();
    document.getElementById('dashboard-view').style.display = 'none';
    document.getElementById('threat-logs-view').style.display = 'none';
    document.getElementById('login-logs-view').style.display = 'none';
    document.getElementById('bank-transactions-view').style.display = 'block';

    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    // If called from nav
    if (event && event.target.closest('.nav-link')) {
        event.target.closest('.nav-link').classList.add('active');
    } else {
        // Find the bank link manually if clicked from auto-alert
        const bankLink = document.querySelector('a[onclick*="showBankView"]');
        if (bankLink) bankLink.classList.add('active');
    }

    if (window.fetchBankTransactions) window.fetchBankTransactions();
}

// Navigation functions
function showDashboard(event) {
    if (event) event.preventDefault();
    document.getElementById('dashboard-view').style.display = 'block';
    document.getElementById('threat-logs-view').style.display = 'none';
    document.getElementById('login-logs-view').style.display = 'none';
    document.getElementById('bank-transactions-view').style.display = 'none';

    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    if (event && event.target.closest('.nav-link')) {
        event.target.closest('.nav-link').classList.add('active');
    }
}

function showLoginLogs(event) {
    if (event) event.preventDefault();
    document.getElementById('dashboard-view').style.display = 'none';
    document.getElementById('threat-logs-view').style.display = 'none';
    document.getElementById('login-logs-view').style.display = 'block';
    document.getElementById('bank-transactions-view').style.display = 'none';

    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    if (event && event.target.closest('.nav-link')) {
        event.target.closest('.nav-link').classList.add('active');
    }

    if (window.fetchLoginLogs) window.fetchLoginLogs();
}

function showAllEmails(event) {
    event.preventDefault();
    document.getElementById('dashboard-view').style.display = 'block';
    document.getElementById('threat-logs-view').style.display = 'none';
    document.getElementById('login-logs-view').style.display = 'none';
    document.getElementById('bank-transactions-view').style.display = 'none';
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    event.target.closest('.nav-link').classList.add('active');
}

function showThreatLogs(event) {
    event.preventDefault();
    document.getElementById('dashboard-view').style.display = 'none';
    document.getElementById('threat-logs-view').style.display = 'block';
    document.getElementById('login-logs-view').style.display = 'none';
    document.getElementById('bank-transactions-view').style.display = 'none';
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    event.target.closest('.nav-link').classList.add('active');
    window.fetchBlockedSenders();
}

// Block handling functions
function handleBlockClick(sender, subject, score, messageId) {
    // For 75-90%, show confirmation modal
    if (score >= 75 && score <= 90) {
        showBlockModal(sender, subject, messageId);
    } else {
        // For 50-74%, block immediately
        blockSender(sender, subject, `Manually blocked (${score}% threat)`, messageId);
    }
}

function showBlockModal(sender, subject, messageId) {
    pendingBlockData = { sender, subject, messageId };
    document.getElementById('modal-sender-info').textContent = `Sender: ${sender}`;
    document.getElementById('modal-subject-info').textContent = `Subject: ${subject}`;
    document.getElementById('block-modal').style.display = 'flex';
    lucide.createIcons();
}

function closeBlockModal() {
    document.getElementById('block-modal').style.display = 'none';
    pendingBlockData = null;
}

function confirmBlock() {
    if (pendingBlockData) {
        blockSender(pendingBlockData.sender, pendingBlockData.subject, 'User confirmed block', pendingBlockData.messageId);
        closeBlockModal();
    }
}

function blockSender(sender, subject, reason, messageId) {
    fetch('/api/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, subject, reason, message_id: messageId })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Blocked: ${sender}`);
                window.fetchEmails();
                window.fetchBlockedSenders();
            } else {
                alert('Error blocking sender');
            }
        })
        .catch(err => console.error('Error blocking sender:', err));
}

function unblockSender(senderEmail) {
    if (!confirm(`Unblock ${senderEmail}?`)) return;

    fetch('/api/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender_email: senderEmail })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Unblocked: ${senderEmail}`);
                window.fetchEmails();
                window.fetchBlockedSenders();
            } else {
                alert('Error unblocking sender');
            }
        })
        .catch(err => console.error('Error unblocking sender:', err));
}
