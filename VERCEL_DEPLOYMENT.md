# Vercel Deployment Guide

This guide will help you deploy the vulnerable blog site to Vercel for testing your AI security agent.

## 🚀 Quick Deployment

### Prerequisites
- [Vercel CLI](https://vercel.com/cli) installed
- Node.js 18+ installed
- Git repository set up

### Step 1: Install Vercel CLI
```bash
npm install -g vercel
```

### Step 2: Login to Vercel
```bash
vercel login
```

### Step 3: Deploy the Application
```bash
vercel --prod
```

## 📁 Project Structure for Vercel

The project is configured for Vercel deployment with the following structure:

```
├── api/                    # Vercel serverless functions
│   ├── index.js           # Main route handler
│   ├── login.js           # Login API endpoint
│   ├── posts.js           # Blog posts API
│   ├── comments.js        # Comments API
│   └── admin/
│       └── data.js        # Admin data API
├── public/                # Static files
│   ├── index.html         # Home page
│   ├── login.html         # Login page
│   ├── admin.html         # Admin page
│   ├── post.html          # Blog post page
│   └── styles.css         # Stylesheet
├── vercel.json            # Vercel configuration
└── package.json           # Dependencies
```

## 🔧 Configuration

### vercel.json
The `vercel.json` file configures:
- API routes for serverless functions
- Static file serving
- Routing rules
- Environment variables

### API Routes
- `/api/login` - Login functionality with SQL injection vulnerabilities
- `/api/posts` - Blog posts data
- `/api/comments` - Comments with XSS vulnerabilities
- `/api/admin/data` - Admin data (no authentication required)

## 🧪 Testing Vulnerabilities

Once deployed, you can test the following vulnerabilities:

### SQL Injection (Login Form)
- Username: `admin' --`
- Username: `' OR '1'='1`
- Username: `' UNION SELECT 1,2,3 --`

### XSS (Comment Section)
- `<script>alert('XSS')</script>`
- `<script>document.cookie</script>`
- `<script>document.body.style.background='red'</script>`

### Information Disclosure
- Access `/admin` page without authentication
- Access `/api/admin/data` for sensitive data

## 🌐 Deployment URL

After deployment, you'll get a URL like:
```
https://your-project-name.vercel.app
```

## 🔍 Available Endpoints

- `GET /` - Home page
- `GET /login` - Login page
- `POST /api/login` - Login API (vulnerable)
- `GET /post/:id` - Blog post page
- `GET /api/posts` - All blog posts
- `GET /api/posts/:id` - Specific blog post
- `GET /api/comments` - All comments
- `GET /api/comments/:postId` - Comments for specific post
- `POST /api/comments` - Add comment (XSS vulnerable)
- `GET /admin` - Admin page (no auth required)
- `GET /api/admin/data` - Admin data (no auth required)

## ⚠️ Security Notice

This application contains **intentional vulnerabilities** for educational purposes and AI agent testing. Do not deploy this in production environments or expose it to the public internet without proper security measures.

## 🛠️ Troubleshooting

### Common Issues

1. **API routes not working**
   - Ensure all API files are in the `api/` directory
   - Check that `vercel.json` routing is correct

2. **Static files not loading**
   - Verify files are in the `public/` directory
   - Check `vercel.json` static file configuration

3. **CORS errors**
   - API routes include CORS headers
   - Check browser console for specific errors

### Development vs Production

- **Development**: Run `npm run dev` for local testing
- **Production**: Deploy to Vercel for live testing

## 📊 Monitoring

Vercel provides built-in monitoring:
- Function execution logs
- Performance metrics
- Error tracking
- Real-time analytics

## 🔄 Updates

To update the deployment:
```bash
vercel --prod
```

This will deploy the latest changes to production. 