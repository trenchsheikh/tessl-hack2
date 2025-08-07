// Vercel serverless function for /api/admin/data
export default function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // VULNERABILITY: No authentication required
    // This endpoint exposes sensitive data without any auth checks
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
        comments: [
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
    console.log('Sensitive data exposed:', adminData);

    res.status(200).json(adminData);
} 