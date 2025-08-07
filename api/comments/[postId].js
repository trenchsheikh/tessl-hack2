// Vercel serverless function for /api/comments/[postId]
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

    const { postId } = req.query;
    const postIdInt = parseInt(postId);

    // Sample comments data
    const comments = [
        {
            id: 1,
            postId: 1,
            author: 'Security Researcher',
            content: 'Excellent introduction! This platform will be perfect for testing various security scenarios. The structured approach to vulnerability testing is exactly what we need.',
            date: '2024-01-15'
        },
        {
            id: 2,
            postId: 1,
            author: 'Penetration Tester',
            content: 'Great resource for practicing ethical hacking techniques. The intentional vulnerabilities are well-documented and easy to understand.',
            date: '2024-01-15'
        },
        {
            id: 3,
            postId: 2,
            author: 'Web Developer',
            content: 'The XSS examples are very helpful for understanding how these attacks work. It\'s eye-opening to see how easily malicious scripts can be executed.',
            date: '2024-01-16'
        },
        {
            id: 4,
            postId: 2,
            author: 'Security Analyst',
            content: 'This is a fantastic learning tool. The practical examples make it much easier to understand the theoretical concepts behind XSS attacks.',
            date: '2024-01-16'
        },
        {
            id: 5,
            postId: 3,
            author: 'Database Administrator',
            content: 'SQL injection is still one of the most critical vulnerabilities. This demonstration shows exactly why proper input validation is so important.',
            date: '2024-01-17'
        }
    ];

    const postComments = comments.filter(c => c.postId === postIdInt);
    res.status(200).json(postComments);
} 