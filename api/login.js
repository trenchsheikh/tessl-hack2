// Vercel API route for login functionality
module.exports = function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // VULNERABILITY: Plaintext password storage in code
    // In real applications, passwords should be hashed and stored in a database
    const HARDCODED_PASSWORDS = {
        'admin': 'admin123',
        'user': 'password123',
        'test': 'test123'
    };

    const { username, password } = req.body;

    // VULNERABILITY: SQL Injection vulnerable login
    // This simulates a vulnerable login system
    if (username && password) {
        // VULNERABILITY: Direct string comparison without proper validation
        if (HARDCODED_PASSWORDS[username] === password) {
            console.log('✅ Login successful:', username);
            return res.status(200).json({ 
                success: true, 
                message: 'Login successful',
                user: { username, role: username === 'admin' ? 'admin' : 'user' }
            });
        }
        
        // VULNERABILITY: SQL Injection test
        // Try these payloads:
        // username: admin' -- 
        // username: admin' OR '1'='1
        // username: ' UNION SELECT 1,2,3 --
        if (username.includes("'") || username.includes('--') || username.includes('OR') || username.includes('UNION')) {
            console.log('🚨 SQL Injection attempt detected:', username);
            return res.status(200).json({ 
                success: true, 
                message: 'SQL Injection successful - admin access granted',
                user: { username: 'admin', role: 'admin' }
            });
        }
    }

    console.log('❌ Login failed:', username);
    return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
    });
} 