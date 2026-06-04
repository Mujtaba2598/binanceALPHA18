const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-secret-key-2024';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';

// ==================== DATA SETUP ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User exists' });
    
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Request sent to owner' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = { 
        email, 
        password: pending[email].password, 
        isOwner: false, 
        isApproved: true, 
        isBlocked: false, 
        apiKey: "", 
        secretKey: "", 
        createdAt: pending[email].requestedAt 
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Approved ${email}` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Rejected ${email}` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} now ${users[email].isBlocked ? 'blocked' : 'unblocked'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({ 
        email, 
        hasApiKeys: !!users[email].apiKey, 
        isOwner: users[email].isOwner, 
        isApproved: users[email].isApproved, 
        isBlocked: users[email].isBlocked 
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0 };
            continue;
        }
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const account = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', false);
            const usdtBalance = account.balances.find(b => b.asset === 'USDT');
            balances[email] = { spot: parseFloat(usdtBalance?.free || 0) };
        } catch (error) {
            balances[email] = { spot: 0, error: true };
        }
    }
    res.json({ success: true, balances });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const timestamp = Date.now();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const queryString = Object.keys(allParams).sort().map(k => `${k}=${allParams[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 15000
    });
    return response.data;
}

async function getTotalBalance(apiKey, secretKey, useDemo = false) {
    try {
        const account = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = account.balances.find(b => b.asset === 'USDT');
        const spotBalance = parseFloat(usdtBalance?.free || 0);
        return spotBalance;
    } catch (error) {
        console.error('Balance error:', error.response?.data || error.message);
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeMarketOrder(apiKey, secretKey, symbol, side, quantity, useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const timestamp = Date.now();
    const params = { symbol, side, type: 'MARKET', quantity: quantity.toFixed(8), timestamp, recvWindow: 5000 };
    const queryString = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}/api/v3/order?${queryString}&signature=${signature}`;
    
    const response = await axios({
        method: 'POST',
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 15000
    });
    return response.data;
}

// ==================== ADVANCED AI SIGNAL ====================
async function getAdvancedAISignal(symbol, useDemo = false) {
    try {
        const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
        
        const ticker = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`);
        const priceChange24h = parseFloat(ticker.data.priceChangePercent);
        const volume24h = parseFloat(ticker.data.volume);
        const high24h = parseFloat(ticker.data.highPrice);
        const low24h = parseFloat(ticker.data.lowPrice);
        const currentPrice = parseFloat(ticker.data.lastPrice);
        
        const range = high24h - low24h;
        const rsi = range > 0 ? ((currentPrice - low24h) / range) * 100 : 50;
        
        const klines = await axios.get(`${baseUrl}/api/v3/klines`, {
            params: { symbol, interval: '5m', limit: 20 }
        });
        const closes = klines.data.map(k => parseFloat(k[4]));
        const ma5 = closes.slice(-5).reduce((a, b) => a + b, 0) / 5;
        const ma10 = closes.slice(-10).reduce((a, b) => a + b, 0) / 10;
        const trend = ma5 > ma10 ? 'UP' : 'DOWN';
        
        const momentum = closes.length >= 2 ? (closes[closes.length - 1] - closes[closes.length - 2]) / closes[closes.length - 2] * 100 : 0;
        const volatility = (high24h - low24h) / currentPrice * 100;
        
        let signal = 'HOLD';
        let confidence = 0;
        let reasons = [];
        
        // STRONG BUY SIGNALS
        if (rsi < 30 && priceChange24h < -3 && volume24h > 500000) {
            signal = 'STRONG_BUY';
            confidence = 0.9;
            reasons.push(`RSI oversold (${rsi.toFixed(1)})`, `Price dropped ${priceChange24h}%`, `High volume`);
        }
        else if (rsi < 40 && trend === 'UP') {
            signal = 'BUY';
            confidence = 0.8;
            reasons.push(`RSI ${rsi.toFixed(1)} in lower range`, `Uptrend confirmed`);
        }
        else if (priceChange24h < -2 && volume24h > 300000) {
            signal = 'BUY';
            confidence = 0.75;
            reasons.push(`Price dip of ${priceChange24h}%`, `Good buying opportunity`);
        }
        else if (momentum > 0 && trend === 'UP' && rsi < 60) {
            signal = 'BUY';
            confidence = 0.7;
            reasons.push(`Positive momentum`, `Uptrend with room to grow`);
        }
        
        // STRONG SELL SIGNALS
        if (rsi > 70 && priceChange24h > 5 && volume24h > 500000) {
            signal = 'STRONG_SELL';
            confidence = 0.9;
            reasons.push(`RSI overbought (${rsi.toFixed(1)})`, `Price pumped ${priceChange24h}%`, `Take profits`);
        }
        else if (rsi > 65 && trend === 'DOWN') {
            signal = 'SELL';
            confidence = 0.8;
            reasons.push(`RSI ${rsi.toFixed(1)} in upper range`, `Downtrend confirmed`);
        }
        else if (priceChange24h > 3 && volume24h > 300000) {
            signal = 'SELL';
            confidence = 0.75;
            reasons.push(`Price pumped ${priceChange24h}%`, `Profit taking opportunity`);
        }
        else if (momentum < 0 && trend === 'DOWN' && rsi > 40) {
            signal = 'SELL';
            confidence = 0.7;
            reasons.push(`Negative momentum`, `Downtrend continuing`);
        }
        
        console.log(`🤖 AI [${symbol}]: ${signal} (${(confidence*100).toFixed(0)}%) | RSI:${rsi.toFixed(1)} Trend:${trend}`);
        
        return { signal, confidence, reasons, currentPrice, rsi, trend, momentum, volatility };
    } catch (error) {
        console.error('AI signal error:', error.message);
        return { signal: 'HOLD', confidence: 0, reasons: ['Error fetching data'], currentPrice: 0 };
    }
}

// ==================== API KEY ROUTES ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    try {
        let { apiKey, secretKey, accountType } = req.body;
        if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
        
        const cleanApi = cleanKey(apiKey);
        const cleanSecret = cleanKey(secretKey);
        const useDemo = (accountType === 'testnet');
        
        const balance = await getTotalBalance(cleanApi, cleanSecret, useDemo);
        
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        res.json({ success: true, message: `API keys saved! Balance: ${balance} USDT`, balance });
    } catch (error) {
        console.error('API key error:', error.response?.data || error.message);
        res.status(401).json({ success: false, message: 'Invalid API keys. Enable Spot & Margin Trading.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        
        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        
        res.json({ success: true, balance, totalBalance: balance, message: `Connected! Balance: ${balance} USDT` });
    } catch (error) {
        console.error('Connection error:', error);
        res.status(401).json({ success: false, message: 'Connection failed. Check API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== CONTINUOUS TRADING ENGINE ====================
const activeSessions = {};
const openPositions = {};

class TradingEngine {
    constructor(sessionId, userEmail, apiKey, secretKey, config, useDemo) {
        this.sessionId = sessionId;
        this.userEmail = userEmail;
        this.apiKey = apiKey;
        this.secretKey = secretKey;
        this.config = config;
        this.useDemo = useDemo;
        this.isActive = true;
        this.currentProfit = 0;
        this.trades = [];
        this.winStreak = 0;
        this.analysisInterval = null;
        this.monitorInterval = null;
        this.startTime = Date.now();
    }
    
    async start() {
        console.log(`🚀 Starting trading engine for ${this.userEmail}`);
        
        this.analysisInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
            if (elapsedHours >= this.config.timeLimit) {
                await this.stop();
                return;
            }
            
            if (this.currentProfit >= this.config.targetProfit) {
                console.log(`🎯 Target reached! Total profit: $${this.currentProfit.toFixed(2)}`);
                await this.stop();
                return;
            }
            
            for (const symbol of this.config.tradingPairs) {
                if (!this.isActive) break;
                
                try {
                    const signal = await getAdvancedAISignal(symbol, this.useDemo);
                    
                    if (signal.signal === 'STRONG_BUY' || signal.signal === 'BUY') {
                        await this.executeTrade(symbol, 'BUY', signal);
                    } else if (signal.signal === 'STRONG_SELL' || signal.signal === 'SELL') {
                        await this.executeTrade(symbol, 'SELL', signal);
                    }
                } catch (error) {
                    console.error(`Analysis error for ${symbol}:`, error.message);
                }
            }
        }, 10000);
        
        this.monitorInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            const userPositions = openPositions[this.userEmail] || [];
            
            for (const position of userPositions) {
                if (position.sessionId !== this.sessionId) continue;
                
                try {
                    const currentPrice = await getCurrentPrice(position.symbol, this.useDemo);
                    let currentProfit = 0;
                    
                    if (position.side === 'BUY') {
                        currentProfit = (currentPrice - position.entryPrice) * position.quantity;
                    } else {
                        currentProfit = (position.entryPrice - currentPrice) * position.quantity;
                    }
                    
                    const profitPercent = (currentProfit / position.positionSize) * 100;
                    
                    if (profitPercent >= position.targetProfitPercent || profitPercent <= position.stopLossPercent) {
                        console.log(`📊 Closing ${position.symbol} ${position.side} - Profit: ${profitPercent.toFixed(2)}%`);
                        await this.closePosition(position);
                    }
                } catch (error) {
                    console.error(`Monitor error for ${position.symbol}:`, error.message);
                }
            }
        }, 5000);
    }
    
    async executeTrade(symbol, side, signal) {
        const userPositions = openPositions[this.userEmail] || [];
        
        const hasOpenPosition = userPositions.some(p => p.sessionId === this.sessionId && p.symbol === symbol);
        if (hasOpenPosition) return;
        
        const balance = await getTotalBalance(this.apiKey, this.secretKey, this.useDemo);
        let positionSize = balance * (this.config.riskLevel === 'low' ? 0.1 : this.config.riskLevel === 'medium' ? 0.15 : 0.2);
        if (positionSize < 3) positionSize = 3;
        if (positionSize > balance * 0.3) positionSize = balance * 0.3;
        
        if (balance < positionSize + 10) {
            console.log(`⚠️ Insufficient balance: ${balance} USDT`);
            return;
        }
        
        const currentPrice = signal.currentPrice || await getCurrentPrice(symbol, this.useDemo);
        const quantity = positionSize / currentPrice;
        
        try {
            console.log(`📈 Executing ${side} for ${symbol} with $${positionSize.toFixed(2)}`);
            const order = await placeMarketOrder(this.apiKey, this.secretKey, symbol, side, quantity, this.useDemo);
            const fillPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            const executedQty = parseFloat(order.executedQty);
            
            const newPosition = {
                sessionId: this.sessionId,
                symbol: symbol,
                side: side,
                quantity: executedQty,
                entryPrice: fillPrice,
                positionSize: positionSize,
                targetProfitPercent: this.config.takeProfit || 2,
                stopLossPercent: this.config.stopLoss || -1,
                openedAt: new Date().toISOString(),
                aiConfidence: signal.confidence,
                aiReasons: signal.reasons
            };
            
            if (!openPositions[this.userEmail]) openPositions[this.userEmail] = [];
            openPositions[this.userEmail].push(newPosition);
            
            this.trades.unshift({
                symbol: symbol,
                side: `${side} OPEN`,
                entryPrice: fillPrice.toFixed(2),
                positionSize: positionSize.toFixed(2),
                aiConfidence: `${(signal.confidence * 100).toFixed(0)}%`,
                aiSignal: signal.signal,
                timestamp: new Date().toISOString()
            });
            
            console.log(`✅ ${side} opened for ${symbol} at $${fillPrice}`);
        } catch (error) {
            console.error(`Trade execution error:`, error.message);
        }
    }
    
    async closePosition(position) {
        try {
            const currentPrice = await getCurrentPrice(position.symbol, this.useDemo);
            const closeSide = position.side === 'BUY' ? 'SELL' : 'BUY';
            const order = await placeMarketOrder(this.apiKey, this.secretKey, position.symbol, closeSide, position.quantity, this.useDemo);
            const fillPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            
            let profit = 0;
            if (position.side === 'BUY') {
                profit = (fillPrice - position.entryPrice) * position.quantity;
            } else {
                profit = (position.entryPrice - fillPrice) * position.quantity;
            }
            
            this.currentProfit += profit;
            this.winStreak = profit > 0 ? this.winStreak + 1 : 0;
            
            this.trades.unshift({
                symbol: position.symbol,
                side: `${position.side} CLOSED`,
                entryPrice: position.entryPrice.toFixed(2),
                exitPrice: fillPrice.toFixed(2),
                profit: profit.toFixed(2),
                profitPercent: ((profit / position.positionSize) * 100).toFixed(2),
                timestamp: new Date().toISOString()
            });
            
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                exitPrice: fillPrice,
                profit: profit,
                profitPercent: (profit / position.positionSize) * 100,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            openPositions[this.userEmail] = (openPositions[this.userEmail] || []).filter(p => p !== position);
            
            console.log(`✅ Closed ${position.symbol} | Profit: $${profit.toFixed(2)} (${((profit / position.positionSize) * 100).toFixed(2)}%) | Total: $${this.currentProfit.toFixed(2)}`);
        } catch (error) {
            console.error(`Close error:`, error.message);
        }
    }
    
    async stop() {
        console.log(`🛑 Stopping trading engine for ${this.userEmail}`);
        this.isActive = false;
        
        if (this.analysisInterval) clearInterval(this.analysisInterval);
        if (this.monitorInterval) clearInterval(this.monitorInterval);
        
        const userPositions = openPositions[this.userEmail] || [];
        for (const position of userPositions) {
            if (position.sessionId === this.sessionId) {
                await this.closePosition(position);
            }
        }
    }
    
    getStatus() {
        const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, this.config.timeLimit - elapsedHours);
        const progressPercent = (this.currentProfit / this.config.targetProfit) * 100;
        
        return {
            isActive: this.isActive,
            currentProfit: this.currentProfit,
            targetProfit: this.config.targetProfit,
            winStreak: this.winStreak,
            timeRemaining: timeRemaining,
            progressPercent: progressPercent,
            openPositions: (openPositions[this.userEmail] || []).filter(p => p.sessionId === this.sessionId).length,
            trades: this.trades.slice(0, 20)
        };
    }
}

const engines = {};

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { targetProfit, timeLimit, riskLevel, tradingPairs, accountType, takeProfit, stopLoss } = req.body;
        
        if (targetProfit < 3) return res.status(400).json({ success: false, message: 'Target profit must be at least $3' });
        if (!timeLimit || timeLimit < 0.1) return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });

        const users = readUsers();
        const user = users[req.user.email];
        if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });

        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');

        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        
        if (balance < 3) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USDT, need at least $3` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        
        const config = {
            targetProfit,
            timeLimit: timeLimit,
            riskLevel: riskLevel || 'medium',
            tradingPairs: tradingPairs || ['BTCUSDT', 'ETHUSDT'],
            takeProfit: takeProfit || 2,
            stopLoss: stopLoss || -1
        };
        
        const engine = new TradingEngine(sessionId, req.user.email, apiKey, secretKey, config, useDemo);
        engines[sessionId] = engine;
        await engine.start();
        
        res.json({ 
            success: true, 
            sessionId, 
            message: `Trading started! Balance: ${balance} USDT | AI analyzes every 10 seconds | Unlimited concurrent trades | Positions close at ${config.takeProfit}% profit or ${config.stopLoss}% loss` 
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (engines[sessionId]) {
        engines[sessionId].stop();
        delete engines[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const engine = engines[sessionId];
    if (!engine) return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
    
    const status = engine.getStatus();
    res.json({
        success: true,
        currentProfit: status.currentProfit,
        targetProfit: status.targetProfit,
        newTrades: status.trades,
        winStreak: status.winStreak,
        timeRemaining: status.timeRemaining,
        progressPercent: status.progressPercent,
        openPositions: status.openPositions,
        isActive: status.isActive
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.json({ success: false, message: 'No API keys' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        
        res.json({ success: true, balance, total: balance });
    } catch (error) {
        console.error('Balance API error:', error);
        res.json({ success: false, message: error.message });
    }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 HALAL TRADING BOT - CONTINUOUS TRADING VERSION`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Login: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Minimum Balance: $3`);
    console.log(`✅ Default Time Limit: 1 hour (configurable higher)`);
    console.log(`✅ AI analyzes market EVERY 10 seconds`);
    console.log(`✅ Unlimited concurrent trades (can open multiple positions)`);
    console.log(`✅ Positions close at 2% profit or -1% loss`);
    console.log(`✅ 100% Halal - Spot Trading Only\n`);
});
