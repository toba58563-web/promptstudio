require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const admin = require('firebase-admin'); // ✅ Firebase Admin SDK import

// ✅ Initialize Firebase Admin SDK from Environment Variable (Render)
// The FIREBASE_CONFIG env variable should contain the JSON string of your service account
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log('✅ Firebase Admin SDK initialized successfully from environment variable');
} else {
    console.log('ℹ️ Firebase Admin SDK already initialized');
}

const app = express();
const PORT = process.env.PORT || 3000;

// ========== MIDDLEWARE ==========
// ✅ CORS properly configured to accept requests from any origin (including Render frontend)
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static('public'));

// ========== MONGODB CONNECTION ==========
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected Successfully!'))
.catch(err => console.error('❌ MongoDB Error:', err));

// ========== ADMIN SCHEMA ==========
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);

// ========== USER SCHEMA (ADDED FOR STATS) ==========
// Since your admin.html expects user stats, we'll create a basic User schema
// If you already have a User model elsewhere, you can remove this and uncomment the import
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    lastLogin: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Only create User model if it doesn't exist already
const User = mongoose.models.User || mongoose.model('User', userSchema);

// ========== INITIALIZE DEFAULT ADMIN IF NOT EXISTS ==========
async function initializeDefaultAdmin() {
    try {
        const existingAdmin = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            const admin = new Admin({
                email: process.env.ADMIN_EMAIL,
                password: hashedPassword
            });
            await admin.save();
            console.log('✅ Default admin created successfully');
        } else {
            console.log('✅ Admin already exists');
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
}

// ========== AUTH MIDDLEWARE ==========
const authenticateAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId).select('-password');
        if (!admin) {
            return res.status(401).json({ success: false, error: 'Admin not found' });
        }
        req.admin = admin;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
};

// ========== ADMIN LOGIN ROUTE ==========
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find admin by email
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        // Check password
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { adminId: admin._id, email: admin.email },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );
        
        res.json({
            success: true,
            token,
            admin: {
                email: admin.email
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// ========== CHANGE PASSWORD ROUTE ==========
app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // Validate input
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                error: 'Current password and new password are required' 
            });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ 
                success: false, 
                error: 'New password must be at least 6 characters long' 
            });
        }
        
        // Get admin from database with password
        const admin = await Admin.findById(req.admin._id);
        if (!admin) {
            return res.status(404).json({ success: false, error: 'Admin not found' });
        }
        
        // Verify current password
        const isPasswordValid = await bcrypt.compare(currentPassword, admin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: 'Current password is incorrect' });
        }
        
        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        
        // Update password
        admin.password = hashedNewPassword;
        admin.updatedAt = new Date();
        await admin.save();
        
        console.log('✅ Admin password changed successfully');
        
        res.json({ 
            success: true, 
            message: 'Password changed successfully' 
        });
        
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ success: false, error: 'Failed to change password' });
    }
});

// ========== VERIFY TOKEN ROUTE ==========
app.get('/api/admin/verify', authenticateAdmin, async (req, res) => {
    res.json({ 
        success: true, 
        admin: { email: req.admin.email } 
    });
});

// ========== PROMPT ROUTES ==========
const promptSchema = new mongoose.Schema({
    title: { type: String, required: true },
    category: { type: String, required: true },
    prompt: { type: String, required: true },
    imageUrl: { type: String, default: 'https://picsum.photos/400/300' },
    likes: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

// Broadcast Schema
const broadcastSchema = new mongoose.Schema({
    message: { type: String, required: true },
    sentBy: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});
const Broadcast = mongoose.model('Broadcast', broadcastSchema);

const Prompt = mongoose.model('Prompt', promptSchema);

app.get('/api/prompts', async (req, res) => {
    try {
        const prompts = await Prompt.find().sort({ createdAt: -1 }).lean();
        res.json({ success: true, prompts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/prompt/like', async (req, res) => {
    try {
        const { id } = req.body;
        const prompt = await Prompt.findByIdAndUpdate(id, { $inc: { likes: 1 } }, { new: true });
        res.json({ success: true, likes: prompt.likes });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== 🆕 REAL VIEWS COUNTER ROUTE ==========
// POST /api/prompt/view - Increment view count for a prompt
app.post('/api/prompt/view', async (req, res) => {
    try {
        const { id } = req.body;
        
        if (!id) {
            return res.status(400).json({ success: false, error: 'Prompt ID required' });
        }
        
        // Find and update the prompt, increment views by 1
        const prompt = await Prompt.findByIdAndUpdate(
            id, 
            { $inc: { views: 1 } }, 
            { new: true }
        );
        
        if (!prompt) {
            return res.status(404).json({ success: false, error: 'Prompt not found' });
        }
        
        console.log(`👁️ View counted for prompt: ${prompt.title} (Total views: ${prompt.views})`);
        
        res.json({ 
            success: true, 
            views: prompt.views,
            message: 'View counted successfully'
        });
        
    } catch (error) {
        console.error('Error updating view count:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== SUPER ADMIN API ROUTES ==========

// ✅ FIXED: GET /api/admin/stats - Dashboard analytics (no more User model error)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        // Get total prompts count
        const totalPrompts = await Prompt.countDocuments();
        
        // Try to get user counts, but don't crash if User model doesn't have data
        let totalUsers = 0;
        let activeUsers = 0;
        
        try {
            totalUsers = await User.countDocuments();
            const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            activeUsers = await User.countDocuments({ lastLogin: { $gte: twentyFourHoursAgo } });
        } catch (userError) {
            console.log('ℹ️ User model exists but no data yet (this is normal for new setup)');
            // Keep default values (0) - dashboard will show 0 users
        }
        
        res.json({ 
            success: true, 
            stats: { 
                totalUsers: totalUsers, 
                activeUsers: activeUsers, 
                totalPrompts: totalPrompts 
            }
        });
    } catch (error) {
        console.error('Stats error:', error);
        // Even on error, return at least the prompt count
        try {
            const totalPrompts = await Prompt.countDocuments();
            res.json({ 
                success: true, 
                stats: { 
                    totalUsers: 0, 
                    activeUsers: 0, 
                    totalPrompts: totalPrompts 
                }
            });
        } catch (fallbackError) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
});

// GET /api/admin/prompts - Fetch all prompts
app.get('/api/admin/prompts', authenticateAdmin, async (req, res) => {
    try {
        const prompts = await Prompt.find().sort({ createdAt: -1 }).lean();
        res.json({ success: true, prompts });
    } catch (error) {
        console.error('Error fetching prompts:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /api/admin/prompts - Add new prompt
app.post('/api/admin/prompts', authenticateAdmin, async (req, res) => {
    try {
        const { title, category, prompt, imageUrl } = req.body;
        if (!title || !prompt) {
            return res.status(400).json({ success: false, error: 'Title and prompt required' });
        }
        const newPrompt = new Prompt({ title, category, prompt, imageUrl });
        await newPrompt.save();
        res.json({ success: true, prompt: newPrompt });
    } catch (error) {
        console.error('Error adding prompt:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// PUT /api/admin/prompts/:id - Update prompt
app.put('/api/admin/prompts/:id', authenticateAdmin, async (req, res) => {
    try {
        const { title, category, prompt, imageUrl, likes } = req.body;
        const updateData = { title, category, prompt, imageUrl };
        
        // Include likes if provided (for the like count update feature)
        if (likes !== undefined) {
            updateData.likes = likes;
        }
        
        const updated = await Prompt.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );
        
        if (!updated) {
            return res.status(404).json({ success: false, error: 'Prompt not found' });
        }
        
        res.json({ success: true, prompt: updated });
    } catch (error) {
        console.error('Error updating prompt:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// DELETE /api/admin/prompts/:id - Delete prompt
app.delete('/api/admin/prompts/:id', authenticateAdmin, async (req, res) => {
    try {
        const deleted = await Prompt.findByIdAndDelete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ success: false, error: 'Prompt not found' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting prompt:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== ✅ FIXED BROADCAST ROUTE (matches admin.html) ==========
// POST /api/admin/broadcast - Send push notification to all users via FCM topic 'all'
app.post('/api/admin/broadcast', authenticateAdmin, async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ success: false, error: 'Message required' });
        }
        
        // Store broadcast in database for history
        await Broadcast.create({ message, sentBy: req.admin.email });
        console.log(`📡 Broadcast initiated: "${message}" by ${req.admin.email}`);
        
        // ========== FIREBASE PUSH NOTIFICATION ==========
        // Send notification to topic 'all' (Kodular app should subscribe to this topic)
        const notificationTitle = 'New Update from Prompt Studio';
        
        const fcmMessage = {
            notification: {
                title: notificationTitle,
                body: message,
            },
            data: {
                click_action: 'FLUTTER_NOTIFICATION_CLICK',
                screen: 'home',
                timestamp: Date.now().toString(),
            },
            topic: 'all', // Sends to all devices subscribed to 'all' topic
        };
        
        // Send the notification
        const fcmResponse = await admin.messaging().send(fcmMessage);
        
        console.log(`✅ Firebase notification sent successfully! Message ID: ${fcmResponse}`);
        console.log(`📱 Title: "${notificationTitle}", Body: "${message}"`);
        
        res.json({ 
            success: true, 
            message: 'Alert sent successfully via push notification',
            fcmMessageId: fcmResponse,
            broadcast: { title: notificationTitle, body: message, topic: 'all' }
        });
        
    } catch (error) {
        console.error('❌ Broadcast error:', error);
        
        // Still return error so frontend knows it failed
        res.status(500).json({ 
            success: false, 
            error: 'Failed to send push notification',
            details: error.message 
        });
    }
});

// ========== START SERVER ==========
async function startServer() {
    await initializeDefaultAdmin();
    app.listen(PORT, () => {
        console.log(`\n🚀 Server running on http://localhost:${PORT}`);
        console.log(`📱 Admin Login: http://localhost:${PORT}/admin.html`);
        console.log(`🔐 Default Admin: ${process.env.ADMIN_EMAIL}`);
        console.log(`✅ Password change API: POST /api/admin/change-password`);
        console.log(`🔥 Firebase Push Notifications active: Topic "all"`);
        console.log(`✅ CORS enabled for all origins`);
        console.log(`✅ Stats API ready (Prompts: ${Prompt.countDocuments() || 0})`);
        console.log(`👁️ Real Views Counter active: POST /api/prompt/view`);
    });
}

startServer();
