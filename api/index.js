// Main Vercel API route for server-side rendering
const path = require('path');
const fs = require('fs');

module.exports = function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const { pathname } = new URL(req.url, `http://${req.headers.host}`);
    
    // Serve static files
    if (pathname.endsWith('.css') || pathname.endsWith('.js') || pathname.endsWith('.ico')) {
        const filePath = path.join(process.cwd(), 'public', pathname);
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath);
            const ext = path.extname(filePath);
            const contentType = {
                '.css': 'text/css',
                '.js': 'application/javascript',
                '.ico': 'image/x-icon'
            }[ext] || 'text/plain';
            
            res.setHeader('Content-Type', contentType);
            return res.status(200).send(content);
        }
    }

    // Route handling
    if (pathname === '/' || pathname === '/index.html') {
        return servePage(res, 'index.html');
    } else if (pathname === '/login' || pathname === '/login.html') {
        return servePage(res, 'login.html');
    } else if (pathname === '/admin' || pathname === '/admin.html') {
        return servePage(res, 'admin.html');
    } else if (pathname.startsWith('/post/')) {
        return servePage(res, 'post.html');
    }

    // Default to index.html
    return servePage(res, 'index.html');
}

function servePage(res, filename) {
    const filePath = path.join(process.cwd(), 'public', filename);
    if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html');
        return res.status(200).send(content);
    } else {
        res.setHeader('Content-Type', 'text/html');
        return res.status(404).send(`
            <html>
                <head><title>404 - Page Not Found</title></head>
                <body>
                    <h1>404 - Page Not Found</h1>
                    <p>The requested page could not be found.</p>
                    <a href="/">Go back to home</a>
                </body>
            </html>
        `);
    }
} 