// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const admin = require("firebase-admin");
const serviceAccount = require("./styledecor-Admin-SDK.json");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 5000;

// Initialize Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Middleware
app.use(cors({
    origin: [process.env.CLIENT_URL || 'http://localhost:5173'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// JWT helpers
const generateAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '15m' });
};
const generateRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' });
};

// JWT verification middleware (cookie)
const verifyJWT = (req, res, next) => {
    const token = req.cookies?.accessToken;
    if (!token) return res.status(401).send({ message: 'Unauthorized access' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send({ message: 'Invalid access token' });
        req.decoded_email = decoded.email;
        req.decoded_role = decoded.role;
        next();
    });
};

const verifyAdmin = (req, res, next) => {
    if (req.decoded_role !== 'admin') return res.status(403).send({ message: 'Forbidden - Admin only' });
    next();
};

// MongoDB setup
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect();

        // All The collection
        const db = client.db('StyleDecorDB');
        const usersCollection = db.collection('users');
        const servicesCollection = db.collection('services')

        app.get('/', (req, res) => res.send('StyleDecor Server is running'));

        // Firebase login: client posts idToken; server verifies and issues cookies
        app.post('/auth/firebase-login', async (req, res) => {
            try {
                const { idToken } = req.body;
                if (!idToken) return res.status(400).send({ message: 'idToken required' });

                const decoded = await admin.auth().verifyIdToken(idToken);
                const email = decoded.email;
                if (!email) return res.status(400).send({ message: 'Invalid Firebase token' });

                const displayName = decoded.name || '';
                const photoURL = decoded.picture || '';

                // Upsert user
                await usersCollection.updateOne(
                    { email },
                    {
                        $setOnInsert: {
                            email,
                            name: displayName,
                            photoURL,
                            role: 'user',
                            createdAt: new Date()
                        }
                    },
                    { upsert: true }
                );

                const user = await usersCollection.findOne({ email });

                const accessToken = generateAccessToken({ email, role: user.role });
                const refreshToken = generateRefreshToken({ email });

                // store refresh token in DB (for revocation)
                await usersCollection.updateOne({ email }, { $set: { refreshToken } });

                const isProd = process.env.NODE_ENV === 'production';

                res.cookie('accessToken', accessToken, {
                    httpOnly: true,
                    secure: isProd,
                    sameSite: 'none',
                    maxAge: 15 * 60 * 1000,
                });
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: isProd,
                    sameSite: 'none',
                    maxAge: 7 * 24 * 60 * 60 * 1000,
                });

                return res.json({ message: 'Login successful', role: user.role });
            } catch (err) {
                console.error('firebase-login error:', err);
                return res.status(401).send({ message: 'Invalid Firebase token' });
            }
        });

        // Refresh endpoint
        app.post('/auth/refresh-token', async (req, res) => {
            try {
                const refreshToken = req.cookies?.refreshToken;
                if (!refreshToken) return res.status(401).send({ message: 'No refresh token' });

                const user = await usersCollection.findOne({ refreshToken });
                if (!user) return res.status(403).send({ message: 'Invalid refresh token' });

                jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
                    if (err) return res.status(403).send({ message: 'Invalid refresh token' });

                    const newAccessToken = generateAccessToken({ email: decoded.email, role: user.role });
                    const isProd = process.env.NODE_ENV === 'production';

                    res.cookie('accessToken', newAccessToken, {
                        httpOnly: true,
                        secure: isProd,
                        sameSite: 'none',
                        maxAge: 15 * 60 * 1000,
                    });

                    return res.json({ message: 'Access token refreshed' });
                });
            } catch (err) {
                console.error('refresh-token error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Logout
        app.post('/auth/logout', async (req, res) => {
            try {
                const refreshToken = req.cookies?.refreshToken;
                if (refreshToken) {
                    await usersCollection.updateOne({ refreshToken }, { $unset: { refreshToken: "" } });
                }

                res.clearCookie('accessToken', { httpOnly: true, sameSite: 'none', secure: process.env.NODE_ENV === 'production' });
                res.clearCookie('refreshToken', { httpOnly: true, sameSite: 'none', secure: process.env.NODE_ENV === 'production' });

                return res.json({ message: 'Logged out' });
            } catch (err) {
                console.error('logout error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Get current user profile
        app.get('/users/me', verifyJWT, async (req, res) => {
            try {
                const email = req.decoded_email;
                const user = await usersCollection.findOne({ email }, { projection: { refreshToken: 0 } });
                if (!user) return res.status(404).send({ message: 'User not found' });
                return res.json({ user });
            } catch (err) {
                console.error(err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Example admin route
        app.get('/admin/data', verifyJWT, verifyAdmin, async (req, res) => {
            return res.json({ message: 'admin only data' });
        });

        // (Optional) legacy users creation route (kept for compatibility)
        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = user.role || 'user';
            user.createdAt = new Date();

            const existing = await usersCollection.findOne({ email: user.email });
            if (existing) return res.send({ message: 'user already exist' });

            const result = await usersCollection.insertOne(user);
            res.json(result);
        });

        //  services related apis

        // get all the services
        app.get('/services', async (req, res) => {
            try {
                const { search, sort, category } = req.query;

                let query = {};

                // Search by title
                if (search) {
                    query.title = { $regex: search, $options: 'i' };
                }

                // Filter by category
                if (category && category !== 'all') {
                    query.category = category;
                }

                let cursor = servicesCollection.find(query);

                // Sorting
                if (sort === 'price-asc') {
                    cursor = cursor.sort({ price: 1 });
                } else if (sort === 'price-desc') {
                    cursor = cursor.sort({ price: -1 });
                } else if (sort === 'newest') {
                    cursor = cursor.sort({ createdAt: -1 });
                }

                const allServices = await cursor.toArray();

                res.send({
                    success: true,
                    count: allServices.length,
                    data: allServices
                });

            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });


        //  Get Single service by id for details:
        app.get('/services/:id', async (req, res) => {
            try {
                const id = req.params.id;

                const service = await servicesCollection.findOne({
                    _id: new ObjectId(id)
                });

                if (!service) {
                    return res.status(404).json({ success: false, message: "Service not found" });
                }

                res.status(200).json({
                    success: true,
                    data: service
                });

            } catch (error) {
                res.status(500).json({ success: false, message: "Server error" });
            }
        });










        app.listen(port, () => console.log(`Server running on port ${port}`));
    } finally {
        // keep DB connection open
    }
}

run().catch(console.dir);


































// const express = require('express');
// const cors = require('cors');
// require('dotenv').config();
// const { MongoClient, ServerApiVersion, } = require('mongodb');
// const admin = require("firebase-admin");
// const serviceAccount = require("./styledecor-Admin-SDK.json");
// const jwt = require('jsonwebtoken');


// const app = express();
// const port = process.env.PORT || 5000;


// // Generate jwt token
// const generateToken = (payload) => {
//     return jwt.sign(payload, process.env.JWT_SECRET, {
//         expiresIn: process.env.JWT_EXPIRES
//     });
// };


// // initialize firebase admin sdk
// admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount)
// });

// // Middleware
// app.use(cors());
// app.use(express.json());

// // Firebase Verification middleware

// const verifyFBToken = async (req, res, next) => {
//     // console.log("headers in the middleware",req.headers.Authorization)
//     const token = req.headers.authorization;
//     if (!token) {
//         return res.status(401).send({ message: 'unauthorized access' })
//     }
//     try {
//         const idToken = token.split(' ')[1];
//         const decoded = await admin.auth().verifyIdToken(idToken)
//         req.decoded_email = decoded.email;
//         console.log('decoded dta', decoded)

//     }
//     catch (err) {
//         return res.status(401).send({ message: "unauthorized access" })
//     }


//     next()
// }

// // Jwt middleware
// const verifyJWT = (req, res, next) => {
//     const authHeader = req.headers.authorization;

//     if (!authHeader) {
//         return res.status(401).send({ message: 'Unauthorized access' });
//     }

//     const token = authHeader.split(' ')[1];

//     jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//         if (err) {
//             return res.status(401).send({ message: 'Unauthorized access' });
//         }

//         req.decoded_email = decoded.email;
//         next();
//     });
// };


// // MongoDB Connection
// const uri = process.env.MONGODB_URI;
// // Create a MongoClient with a MongoClientOptions object to set the Stable API version
// const client = new MongoClient(uri, {
//     serverApi: {
//         version: ServerApiVersion.v1,
//         strict: true,
//         deprecationErrors: true,
//     }
// });

// async function run() {
//     try {
//         console.log("Pinged your deployment. You successfully connected to MongoDB!");

//         const db = client.db('StyleDecorDB');
//         const usersCollection = db.collection('users');

//         // Basic Route
//         app.get('/', (req, res) => {
//             res.send('StyleDecor Server is running');
//         });

//         // User Related Api
//         app.post('/users', async (req, res) => {
//             const user = req.body;
//             user.role = 'user';
//             user.createdAt = new Date();

//             const email = user.email
//             const userExist = await usersCollection.findOne({ email })
//             if (userExist) {
//                 return res.send({ message: 'user already exist' })
//             }
//             const result = await usersCollection.insertOne(user);
//             res.json(result); // json => send
//         })











//         // Start Server
//         app.listen(port, () => {
//             console.log(`Server is running on port ${port}`);
//         });

//     } finally {
//         // Ensures that the client will close when you finish/error
//         // await client.close();
//     }
// }
// run().catch(console.dir);