// Theme Toggle
const themeBtn = document.getElementById('themeBtn');
const themeIcon = themeBtn.querySelector('i');

// Check for saved theme or prefer color scheme
const savedTheme = localStorage.getItem('theme') || 
                  (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

if (savedTheme === 'dark') {
    document.body.classList.add('dark-mode');
    themeIcon.className = 'fas fa-sun';
}

themeBtn.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    const isDarkMode = document.body.classList.contains('dark-mode');
    
    themeIcon.className = isDarkMode ? 'fas fa-sun' : 'fas fa-moon';
    localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
});

// Tab Switching
const tabBtns = document.querySelectorAll('.tab-btn');
tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // Remove active class from all tabs and contents
        tabBtns.forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        
        // Add active class to clicked tab and corresponding content
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab + 'Tab').classList.add('active');
        
        // Clear results when switching tabs
        clearResults();
    });
});

// Analysis Functions
document.getElementById('analyzeBtn').addEventListener('click', analyzeSingleUrl);
document.getElementById('batchAnalyzeBtn').addEventListener('click', analyzeBatchUrls);

// Clear Buttons
document.getElementById('clearSingle').addEventListener('click', clearSingleInput);
document.getElementById('clearBatch').addEventListener('click', clearBatchInput);
document.getElementById('clearResults').addEventListener('click', clearAllResults);

// Export Results
document.getElementById('exportResults').addEventListener('click', exportResults);

// Enter key support for single URL
document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeSingleUrl();
});

// Example URLs for batch tab
const exampleUrls = `https://accounts.google.com/ServiceLogin
https://login.microsoftonline.com/
https://secure-paypal.co/login
https://xn--pple-43d.com/verify
https://gοοgle-support.com/signin`;

// Initialize with example URLs in batch tab
document.getElementById('batchUrls').value = exampleUrls;

function analyzeSingleUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        showNotification('Please enter a URL to analyze', 'warning');
        return;
    }

    showLoading(true);
    clearResults();

    fetch('/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        showLoading(false);
        if (data.error) {
            throw new Error(data.error);
        }
        displaySingleResult(data);
        showNotification('URL analysis completed successfully!', 'success');
    })
    .catch(error => {
        showLoading(false);
        console.error('Error:', error);
        showNotification('Error analyzing URL: ' + error.message, 'error');
    });
}

function analyzeBatchUrls() {
    const urlsText = document.getElementById('batchUrls').value.trim();
    if (!urlsText) {
        showNotification('Please enter URLs to analyze', 'warning');
        return;
    }

    const urls = urlsText.split('\n').filter(url => url.trim());
    if (urls.length === 0) {
        showNotification('Please enter valid URLs', 'warning');
        return;
    }

    if (urls.length > 50) {
        showNotification('Please limit batch analysis to 50 URLs maximum', 'warning');
        return;
    }

    showLoading(true);
    clearResults();

    fetch('/batch-analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ urls: urls })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        showLoading(false);
        if (data.error) {
            throw new Error(data.error);
        }
        displayBatchResults(data.results);
        showNotification(`Batch analysis completed! Processed ${data.results.length} URLs`, 'success');
    })
    .catch(error => {
        showLoading(false);
        console.error('Error:', error);
        showNotification('Error analyzing URLs: ' + error.message, 'error');
    });
}

function displaySingleResult(result) {
    document.getElementById('noResults').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';

    const riskClass = getRiskClass(result.final_verdict);
    const riskIcon = getRiskIcon(result.final_verdict);

    const resultHTML = `
        <div class="result-card ${riskClass}">
            <div class="result-header">
                <span class="risk-badge ${riskClass}">
                    ${riskIcon}
                    ${result.final_verdict.replace('_', ' ')}
                </span>
                <div style="font-size: 0.9rem; color: var(--secondary);">
                    ${(result.ml_result.probability * 100).toFixed(1)}% phishing probability
                </div>
            </div>
            
            <div class="url-display">${escapeHtml(result.url)}</div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value ${getProbabilityClass(result.ml_result.probability)}">
                        ${(result.ml_result.probability * 100).toFixed(1)}%
                    </div>
                    <div class="stat-label">Phishing Probability</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value ${getRiskScoreClass(result.homoglyph_analysis.homoglyph_risk_score)}">
                        ${result.homoglyph_analysis.homoglyph_risk_score.toFixed(1)}%
                    </div>
                    <div class="stat-label">Homoglyph Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">
                        ${result.homoglyph_analysis.homoglyph_count}
                    </div>
                    <div class="stat-label">Suspicious Characters</div>
                </div>
            </div>

            <div class="details-grid">
                <div class="detail-item">
                    <span class="detail-label">ML Verdict</span>
                    <span class="detail-value">${result.ml_result.verdict}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence</span>
                    <span class="detail-value">${result.ml_result.confidence}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Homoglyph Detected</span>
                    <span class="detail-value">${result.homoglyph_analysis.is_suspicious_homoglyph ? 'Yes' : 'No'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Normalized URL</span>
                    <span class="detail-value" style="font-family: monospace; font-size: 0.9rem;">${escapeHtml(result.homoglyph_analysis.normalized_url)}</span>
                </div>
            </div>

            ${result.homoglyph_analysis.suspicious_chars.length > 0 ? `
                <div style="margin-top: 1rem; padding: 1rem; background: var(--light); border-radius: 12px;">
                    <strong style="color: var(--dark);">Suspicious Characters:</strong> 
                    <span style="font-family: monospace; color: var(--danger); font-weight: 600;">
                        ${result.homoglyph_analysis.suspicious_chars.join(', ')}
                    </span>
                </div>
            ` : ''}

            ${result.homoglyph_analysis.multi_char_homoglyphs && result.homoglyph_analysis.multi_char_homoglyphs.length > 0 ? `
                <div style="margin-top: 1rem; padding: 1rem; background: var(--light); border-radius: 12px;">
                    <strong style="color: var(--dark);">Multi-char Homoglyphs:</strong> 
                    <span style="font-family: monospace; color: var(--warning); font-weight: 600;">
                        ${result.homoglyph_analysis.multi_char_homoglyphs.join(', ')}
                    </span>
                </div>
            ` : ''}
        </div>
    `;

    document.getElementById('singleResult').innerHTML = resultHTML;
}

function displayBatchResults(results) {
    document.getElementById('noResults').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('batchResults').style.display = 'block';

    // Summary statistics
    const highRiskCount = results.filter(r => getRiskClass(r.final_verdict) === 'high-risk').length;
    const mediumRiskCount = results.filter(r => getRiskClass(r.final_verdict) === 'medium-risk').length;
    const lowRiskCount = results.filter(r => getRiskClass(r.final_verdict) === 'low-risk').length;

    let batchHTML = `
        <div class="batch-summary">
            <h3 style="margin-bottom: 1rem; color: var(--dark);">Batch Analysis Summary</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value high">${highRiskCount}</div>
                    <div class="stat-label">High Risk URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value medium">${mediumRiskCount}</div>
                    <div class="stat-label">Medium Risk URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value low">${lowRiskCount}</div>
                    <div class="stat-label">Low Risk URLs</div>
                </div>
            </div>
        </div>
    `;
    
    results.forEach((result, index) => {
        const riskClass = getRiskClass(result.final_verdict);
        const riskIcon = getRiskIcon(result.final_verdict);

        batchHTML += `
            <div class="batch-result-item ${riskClass}">
                <div class="batch-url">${escapeHtml(result.url)}</div>
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <span class="risk-badge ${riskClass}" style="font-size: 0.8rem;">
                        ${riskIcon}
                        ${result.final_verdict.replace('_', ' ')}
                    </span>
                    <span style="color: var(--secondary); font-size: 0.9rem;">
                        ${(result.ml_result.probability * 100).toFixed(1)}%
                    </span>
                </div>
            </div>
        `;
    });

    document.getElementById('batchResults').innerHTML = batchHTML;
}

// Utility Functions
function getRiskClass(verdict) {
    if (verdict.includes('HIGH')) return 'high-risk';
    if (verdict.includes('MEDIUM') || verdict.includes('SUSPICIOUS')) return 'medium-risk';
    return 'low-risk';
}

function getRiskIcon(verdict) {
    if (verdict.includes('HIGH')) return '<i class="fas fa-exclamation-triangle"></i>';
    if (verdict.includes('MEDIUM') || verdict.includes('SUSPICIOUS')) return '<i class="fas fa-exclamation-circle"></i>';
    return '<i class="fas fa-check-circle"></i>';
}

function getProbabilityClass(probability) {
    if (probability > 0.7) return 'high';
    if (probability > 0.4) return 'medium';
    return 'low';
}

function getRiskScoreClass(score) {
    if (score > 20) return 'high';
    if (score > 10) return 'medium';
    return 'low';
}

function showLoading(show) {
    document.getElementById('loading').style.display = show ? 'block' : 'none';
    document.getElementById('analyzeBtn').disabled = show;
    document.getElementById('batchAnalyzeBtn').disabled = show;
}

function clearResults() {
    document.getElementById('singleResult').innerHTML = '';
    document.getElementById('batchResults').innerHTML = '';
    document.getElementById('batchResults').style.display = 'none';
    document.getElementById('noResults').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';
}

function clearSingleInput() {
    document.getElementById('urlInput').value = '';
    clearResults();
    showNotification('Single URL input cleared', 'info');
}

function clearBatchInput() {
    document.getElementById('batchUrls').value = '';
    clearResults();
    showNotification('Batch URLs input cleared', 'info');
}

function clearAllResults() {
    clearResults();
    showNotification('All results cleared', 'info');
}

function exportResults() {
    // Simple export functionality - could be enhanced with CSV/JSON export
    const results = document.getElementById('resultsSection').innerText;
    if (!results || results.includes('No Analysis Yet') || results.includes('Ready to Scan')) {
        showNotification('No results to export', 'warning');
        return;
    }

    const blob = new Blob([results], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-analysis-results.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Results exported successfully', 'success');
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Notification System
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
    `;

    // Add notification styles
    if (!document.querySelector('#notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 100px;
                right: 20px;
                background: var(--card-bg);
                padding: 16px 20px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                border: 1px solid var(--card-border);
                z-index: 10000;
                animation: slideInRight 0.3s ease;
                max-width: 400px;
                backdrop-filter: blur(20px);
            }
            .notification-content {
                display: flex;
                align-items: center;
                gap: 12px;
                color: var(--dark);
                font-weight: 500;
            }
            .notification-success { border-left: 4px solid var(--success); }
            .notification-error { border-left: 4px solid var(--danger); }
            .notification-warning { border-left: 4px solid var(--warning); }
            .notification-info { border-left: 4px solid var(--primary); }
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOutRight {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(styles);
    }

    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}