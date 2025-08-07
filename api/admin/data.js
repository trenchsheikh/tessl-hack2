// Simple API for admin data (vulnerable - no authentication)
module.exports = function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // VULNERABILITY: No authentication required
    const adminData = {
        users: [
            { id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' },
            { id: 2, username: 'user1', email: 'user1@example.com', role: 'user' },
            { id: 3, username: 'user2', email: 'user2@example.com', role: 'user' }
        ],
        posts: [
            {
                id: 1,
                title: '🔒 Introduction to Web Security Testing',
                author: 'Security Team',
                date: '2024-01-15'
            },
            {
                id: 2,
                title: '🚨 Understanding Cross-Site Scripting (XSS)',
                author: 'Security Researcher',
                date: '2024-01-16'
            },
            {
                id: 3,
                title: '🔐 SQL Injection: The Classic Attack',
                author: 'Database Security Expert',
                date: '2024-01-17'
            }
        ],
        systemInfo: {
            version: '1.0.0',
            lastBackup: '2024-01-15',
            serverStatus: 'running',
            database: 'SQLite (in-memory)',
            environment: 'production'
        }
    };

    console.log('🚨 VULNERABILITY: Admin data accessed without authentication');
    res.status(200).json(adminData);
} 