// Simple API for comments
module.exports = function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const comments = [
        {
            id: 1,
            postId: 1,
            author: 'Security Researcher',
            content: 'Excellent introduction! This platform will be perfect for testing various security scenarios.',
            date: '2024-01-15'
        },
        {
            id: 2,
            postId: 1,
            author: 'Penetration Tester',
            content: 'Great resource for practicing ethical hacking techniques.',
            date: '2024-01-15'
        },
        {
            id: 3,
            postId: 2,
            author: 'Web Developer',
            content: 'The XSS examples are very helpful for understanding how these attacks work.',
            date: '2024-01-16'
        }
    ];

    if (req.method === 'GET') {
        return res.status(200).json(comments);
    }
    
    if (req.method === 'POST') {
        const { postId, author, content } = req.body;

        // VULNERABILITY: No input sanitization - XSS vulnerable
        const newComment = {
            id: Math.floor(Math.random() * 1000) + 1,
            postId: parseInt(postId),
            author: author,
            content: content, // VULNERABILITY: No sanitization
            date: new Date().toISOString().split('T')[0]
        };

        console.log('VULNERABILITY: XSS payload stored:', content);
        return res.status(200).json({ success: true, comment: newComment });
    }

    return res.status(405).json({ error: 'Method not allowed' });
} 