// Vercel serverless function for /api/posts
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

    const blogPosts = [
        {
            id: 1,
            title: '🔒 Introduction to Web Security Testing',
            content: '<p>Welcome to our intentionally vulnerable blog platform designed for security testing and AI agent evaluation.</p>',
            author: 'Security Team',
            date: '2024-01-15'
        },
        {
            id: 2,
            title: '🚨 Understanding Cross-Site Scripting (XSS)',
            content: '<p>Cross-Site Scripting (XSS) is one of the most common web application vulnerabilities.</p>',
            author: 'Security Researcher',
            date: '2024-01-16'
        },
        {
            id: 3,
            title: '🔐 SQL Injection: The Classic Attack',
            content: '<p>SQL Injection remains one of the most dangerous web application vulnerabilities.</p>',
            author: 'Database Security Expert',
            date: '2024-01-17'
        }
    ];

    res.status(200).json(blogPosts);
} 