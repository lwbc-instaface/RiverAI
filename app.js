// Load environment variables
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();

// Configuration with environment variables
const config = {
    clientId: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI || 'https://instaface.app.n8n.cloud/webhook/logins',
    encryptionKey: process.env.ENCRYPTION_KEY, // Additional key for extra security
    port: process.env.PORT || 3000
};

// Validate required environment variables
function validateConfig() {
    const required = ['FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET', 'ENCRYPTION_KEY'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
}

// In-memory store (replace with your preferred database)
let tokenStore = new Map();

// Encryption helper
function encryptToken(token, hashKey) {
    const key = crypto.createHash('sha256')
        .update(hashKey + config.encryptionKey)
        .digest();
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Webhook endpoint
app.get('/webhook/logins', async (req, res) => {
    try {
        // Step 1: Exchange code for user access token
        const tokenResponse = await axios.get('https://graph.facebook.com/v20.0/oauth/access_token', {
            params: {
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: req.query.code,
                redirect_uri: config.redirectUri
            }
        });
        
        const userAccessToken = tokenResponse.data.access_token;
        
        // Step 2: Get user details
        const userResponse = await axios.get('https://graph.facebook.com/me', {
            params: {
                fields: 'id,name,email',
                access_token: userAccessToken
            }
        });
        
        const userId = userResponse.data.id;
        
        // Step 3: Get page access token
        const pageTokenResponse = await axios.get('https://graph.facebook.com/v20.0/me/accounts', {
            params: {
                access_token: userAccessToken
            }
        });
        
        const pageAccessToken = pageTokenResponse.data.data[0].access_token;
        
        // Step 4: Generate hash key and encrypt token
        const hashKey = crypto.createHash('sha256')
            .update(`${userId} ${new Date().toISOString()}`)
            .digest('hex');
            
        const encryptedToken = encryptToken(pageAccessToken, hashKey);
        
        // Store encrypted token with user info
        tokenStore.set(userId, {
            encryptedToken,
            hashKey,
            name: userResponse.data.name,
            email: userResponse.data.email,
            timestamp: new Date()
        });
        
        // Return success page
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Thank You!</title>
                <style>
                    body { font-family: Arial; text-align: center; margin-top: 50px; }
                </style>
            </head>
            <body>
                <h1>Thank You!</h1>
                <p>For powering your Facebook page with River AI.</p>
            </body>
            </html>
        `);
        
    } catch (error) {
        console.error('Error processing webhook:', error);
        res.status(500).send('An error occurred');
    }
});

// Initial configuration validation
validateConfig();

// Start server
app.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
});
