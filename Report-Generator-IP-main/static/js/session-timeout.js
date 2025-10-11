/**
 * Session Timeout Manager
 * Handles session timeout warnings and automatic logout
 */

class SessionTimeoutManager {
    constructor() {
        this.warningTime = 5 * 60 * 1000; // 5 minutes before timeout
        this.checkInterval = 60 * 1000; // Check every minute
        this.lastActivity = Date.now();
        this.warningShown = false;
        this.checkTimer = null;
        this.warningTimer = null;
        
        this.init();
    }

    init() {
        // Track user activity
        this.trackActivity();
        
        // Start periodic checks
        this.startChecks();
        
        // Show warning modal if needed
        this.createWarningModal();
    }

    trackActivity() {
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
        
        events.forEach(event => {
            document.addEventListener(event, () => {
                this.lastActivity = Date.now();
                this.warningShown = false;
                this.hideWarning();
            }, true);
        });
    }

    startChecks() {
        this.checkTimer = setInterval(() => {
            this.checkSessionTimeout();
        }, this.checkInterval);
    }

    checkSessionTimeout() {
        const now = Date.now();
        const timeSinceActivity = now - this.lastActivity;
        const sessionTimeout = 60 * 60 * 1000; // 1 hour
        
        if (timeSinceActivity > sessionTimeout) {
            // Session has expired
            this.logout();
        } else if (timeSinceActivity > sessionTimeout - this.warningTime && !this.warningShown) {
            // Show warning
            this.showWarning(sessionTimeout - timeSinceActivity);
        }
    }

    createWarningModal() {
        // Remove existing modal if any
        const existing = document.getElementById('session-warning-modal');
        if (existing) {
            existing.remove();
        }

        const modal = document.createElement('div');
        modal.id = 'session-warning-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 10000;
            font-family: Arial, sans-serif;
        `;

        modal.innerHTML = `
            <div style="
                background: white;
                padding: 2rem;
                border-radius: 8px;
                text-align: center;
                max-width: 400px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            ">
                <h3 style="color: #d32f2f; margin-top: 0;">Session Timeout Warning</h3>
                <p>Your session will expire in <span id="timeout-countdown">5:00</span> minutes.</p>
                <p>Click "Stay Logged In" to continue your session.</p>
                <div style="margin-top: 1.5rem;">
                    <button id="stay-logged-in" style="
                        background: #4caf50;
                        color: white;
                        border: none;
                        padding: 0.75rem 1.5rem;
                        border-radius: 4px;
                        cursor: pointer;
                        margin-right: 1rem;
                        font-size: 1rem;
                    ">Stay Logged In</button>
                    <button id="logout-now" style="
                        background: #f44336;
                        color: white;
                        border: none;
                        padding: 0.75rem 1.5rem;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 1rem;
                    ">Logout Now</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Add event listeners
        document.getElementById('stay-logged-in').addEventListener('click', () => {
            this.stayLoggedIn();
        });

        document.getElementById('logout-now').addEventListener('click', () => {
            this.logout();
        });
    }

    showWarning(timeRemaining) {
        this.warningShown = true;
        const modal = document.getElementById('session-warning-modal');
        const countdown = document.getElementById('timeout-countdown');
        
        modal.style.display = 'flex';
        
        // Start countdown
        const startTime = Date.now();
        const updateCountdown = () => {
            const elapsed = Date.now() - startTime;
            const remaining = Math.max(0, timeRemaining - elapsed);
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            countdown.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            if (remaining > 0) {
                this.warningTimer = setTimeout(updateCountdown, 1000);
            } else {
                this.logout();
            }
        };
        
        updateCountdown();
    }

    hideWarning() {
        const modal = document.getElementById('session-warning-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        if (this.warningTimer) {
            clearTimeout(this.warningTimer);
            this.warningTimer = null;
        }
    }

    stayLoggedIn() {
        this.hideWarning();
        this.lastActivity = Date.now();
        this.warningShown = false;
        
        // Optionally refresh CSRF token
        if (window.csrfManager) {
            window.csrfManager.refreshToken();
        }
    }

    logout() {
        // Clear timers
        if (this.checkTimer) {
            clearInterval(this.checkTimer);
        }
        if (this.warningTimer) {
            clearTimeout(this.warningTimer);
        }
        
        // Redirect to logout
        window.location.href = '/logout';
    }

    destroy() {
        if (this.checkTimer) {
            clearInterval(this.checkTimer);
        }
        if (this.warningTimer) {
            clearTimeout(this.warningTimer);
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    window.sessionTimeoutManager = new SessionTimeoutManager();
});
