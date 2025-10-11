/**
 * CSRF Token Management
 * Handles CSRF token retrieval and form submission with tokens
 */

class CSRFManager {
    constructor() {
        this.token = null;
        this.init();
    }

    async init() {
        try {
            // Fetch CSRF token from server
            const response = await fetch('/csrf-token');
            if (response.ok) {
                const data = await response.json();
                this.token = data.csrf_token;
                
                // Store in meta tag for easy access
                this.setMetaToken();
            }
        } catch (error) {
            console.warn('Failed to fetch CSRF token:', error);
        }
    }

    setMetaToken() {
        // Remove existing meta tag if any
        const existing = document.querySelector('meta[name="csrf-token"]');
        if (existing) {
            existing.remove();
        }

        // Add new meta tag
        const meta = document.createElement('meta');
        meta.name = 'csrf-token';
        meta.content = this.token;
        document.head.appendChild(meta);
    }

    getToken() {
        return this.token;
    }

    addToForm(form) {
        if (!this.token) return;

        // Check if token already exists in form
        const existingInput = form.querySelector('input[name="csrf_token"]');
        if (existingInput) {
            existingInput.value = this.token;
            return;
        }

        // Add hidden input with CSRF token
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = this.token;
        form.appendChild(input);
    }

    addToHeaders(headers = {}) {
        if (!this.token) return headers;
        
        return {
            ...headers,
            'X-CSRF-Token': this.token
        };
    }

    async refreshToken() {
        try {
            const response = await fetch('/csrf-refresh', {
                method: 'POST',
                headers: this.addToHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                this.token = data.csrf_token;
                this.setMetaToken();
                return true;
            }
        } catch (error) {
            console.warn('Failed to refresh CSRF token:', error);
        }
        return false;
    }
}

// Global instance
window.csrfManager = new CSRFManager();

// Auto-add CSRF tokens to all forms on page load
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        if (form.method.toLowerCase() === 'post' && !form.querySelector('input[name="csrf_token"]')) {
            window.csrfManager.addToForm(form);
        }
    });
});

// Intercept fetch requests to add CSRF token to POST requests
const originalFetch = window.fetch;
window.fetch = function(url, options = {}) {
    if (options.method && options.method.toLowerCase() === 'post') {
        options.headers = window.csrfManager.addToHeaders(options.headers);
    }
    return originalFetch(url, options);
};
