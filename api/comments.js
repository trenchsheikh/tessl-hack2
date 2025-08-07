// Vercel serverless function for /api/comments (POST)
export default function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { postId, author, content } = req.body;

    // VULNERABILITY: No input sanitization
    // Raw HTML and JavaScript are stored and will be executed when displayed
    const newComment = {
        id: Math.floor(Math.random() * 1000) + 1,
        postId: parseInt(postId),
        author: author, // VULNERABILITY: No sanitization
        content: content, // VULNERABILITY: No sanitization - XSS vulnerable
        date: new Date().toISOString().split('T')[0]
    };

    console.log('VULNERABILITY: XSS payload stored:', content);
    res.status(200).json({ success: true, comment: newComment });
} 