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
    encryptionKey: process.env.ENCRYPTION_KEY,
    port: process.env.PORT || 3000
};

// Global variable store (simulating N8N variables)
const workflowVariables = new Map();

// Helper function to set workflow variables
function setWorkflowVariable(name, value) {
    workflowVariables.set(name, value);
    console.log(`Variable set: ${name}`); // For debugging
}

// Helper function to get workflow variables
function getWorkflowVariable(name) {
    return workflowVariables.get(name);
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
        
        // Step 2: Get user details and store in workflow variables
        const userResponse = await axios.get('https://graph.facebook.com/me', {
            params: {
                fields: 'id,name,email',
                access_token: userAccessToken
            }
        });
        
        // Store user info in workflow variables
        setWorkflowVariable('userId', userResponse.data.id);
        setWorkflowVariable('userName', userResponse.data.name);
        setWorkflowVariable('userEmail', userResponse.data.email);
        
        // Step 3: Get page access token
        const pageTokenResponse = await axios.get('https://graph.facebook.com/v20.0/me/accounts', {
            params: {
                access_token: userAccessToken
            }
        });
        
        const pageAccessToken = pageTokenResponse.data.data[0].access_token;
        
        // Step 4: Generate hash key and encrypt token
        const hashKey = crypto.createHash('sha256')
            .update(`${userResponse.data.id} ${new Date().toISOString()}`)
            .digest('hex');
            
        const encryptedToken = encryptToken(pageAccessToken, hashKey);
        
        // Store encrypted token with user info
        tokenStore.set(userResponse.data.id, {
            encryptedToken,
            hashKey,
            name: userResponse.data.name,
            email: userResponse.data.email,
            timestamp: new Date()
        });

        // Store token info in workflow variables
        setWorkflowVariable('encryptedToken', encryptedToken);
        setWorkflowVariable('hashKey', hashKey);
        
        // Example of accessing stored variables
        console.log('Stored user info:', {
            name: getWorkflowVariable('userName'),
            email: getWorkflowVariable('userEmail'),
            id: getWorkflowVariable('userId')
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

// Start server
app.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
});
