const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('./config');
const {authenticator} = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

//initialize express
const app = express();

//middleware
app.use(express.json());

//initialize cache
const cache = new NodeCache();

//initialize database
const users = Datastore.create('Users.db');

//initialize invalid token database
const userInvalidToken = Datastore.create('UserInvalidTokens.db');

//initialize refresh token database
const userRefreshTokens = Datastore.create('UserRefreshTokens.db');

//default route
app.get('/', (req, res) => {
  res.send('Rest API Authentication and Authorization with JWT');
});

//register route
app.post('/api/auth/register', async (req, res) => {
    try {
        const {name, email, password, role} = req.body;

        //check if all fields are filled
        if(!name || !email || !password) {
            return res.status(422).json({message: 'Please fill in all fields'});
        }

        //check if email is valid
        if(await users.findOne({email})) {
            return res.status(409).json({message: 'Email already exists'});
        }

        //check if name is valid
        if(await users.findOne({name})) {
            return res.status(409).json({message: 'Name already exists'});
        }

        //hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        //insert user into database
        const newUser = await users.insert({name, email, password: hashedPassword, role: role ?? 'member','2faEnable':false, '2faSecret':null});

        //return response
        return res.status(201).json({message: 'User registered successfully',id: newUser._id});

    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//login route
app.post('/api/auth/login', async (req, res) => {
    try {
        const {email, password} = req.body;

        //check if all fields are filled
        if(!email || !password) {
            return res.status(422).json({message: 'Please fill in all fields'});
        }

        //check if user exists
        const user = await users.findOne({email});

        if(!user) {
            return res.status(401).json({message: 'Email or password is incorrect'});
        }

        //check if password is correct
        const passwordMatch = await bcrypt.compare(password, user.password);

        if(!passwordMatch) {
            return res.status(401).json({message: 'Email or password is incorrect'});
        }   

        //check if 2fa is enabled
        if(user['2faEnable']) {
            //generate temporary token
            const tempToken = crypto.randomUUID();

            //set temporary token in cache
            cache.set(config.cacheTemporaryTokenPrefix = tempToken, user._id, config.cacheTemporaryTokenExpiresInSeconds);   

            //return response
            return res.status(200).json({tempToken, expiresInSeconds: config.cacheTemporaryTokenExpiresInSeconds});
        } else {
            //generate access token
            const accessToken = jwt.sign({userId: user._id}, config.accessTokenSecret, {subject: "accessApi", expiresIn: config.accessTokenExpiresIn});

            //generate refresh token
            const refreshToken = jwt.sign({userId: user._id}, config.refreshTokenSecret, {subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn});

            //insert refresh token into database
            await userRefreshTokens.insert({userId: user._id, refreshToken});

            //return response
            return res.status(200).json({message: "Welcome back",id: user._id, name: user.name, email: user.email, accessToken, refreshToken});
        }

    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

app.post('/api/auth/login/2fa', async (req, res) => {
    try {
        const {tempToken, totp} = req.body;

        if(!tempToken || !totp) {
            return res.status(422).json({message: 'Temporary token and TOTP are required'});
        }

        const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);

        if(!userId) {
            return res.status(401).json({message: 'Temporary token is invalid or expired'});
        }

        const user = await users.findOne({_id: userId});

        const verified = authenticator.check(totp, user['2faSecret']);

        if(!verified) {
            return res.status(400).json({message: 'TOTP is invalid or expired'});
        }

        //generate access token
        const accessToken = jwt.sign({userId: user._id}, config.accessTokenSecret, {subject: "accessApi", expiresIn: config.accessTokenExpiresIn});

        //generate refresh token
        const refreshToken = jwt.sign({userId: user._id}, config.refreshTokenSecret, {subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn});

        //insert refresh token into database
        await userRefreshTokens.insert({userId: user._id, refreshToken});

        //return response
        return res.status(200).json({message: "Welcome back",id: user._id, name: user.name, email: user.email, accessToken, refreshToken});
    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//refresh token route
app.post('/api/auth/refresh-token', async (req, res) => {
    try {
        //get refresh token from request body
        const { refreshToken} = req.body;

        //check if refresh token is sent
        if(!refreshToken) {
            return res.status(401).json({message: 'Refresh token is required'});
        }

        //verify refresh token
        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        //check if refresh token exists in database
        const userRefreshToken = await userRefreshTokens.findOne({userId: decodedRefreshToken.userId, refreshToken});

        //check if refresh token exists
        if(!userRefreshToken) {
            return res.status(401).json({message: 'Invalid or expired refresh token'});
        };

        //remove refresh token from database
        await userRefreshTokens.remove({_id: userRefreshToken._id});
        //compact datafile
        await userRefreshTokens.compactDatafile();

        //generate access token
        const accessToken = jwt.sign({userId: decodedRefreshToken.userId}, config.accessTokenSecret, {subject: "accessApi", expiresIn: config.accessTokenExpiresIn});

        //generate new refresh token
        const newRefreshToken = jwt.sign({userId: decodedRefreshToken.userId}, config.refreshTokenSecret, {subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn});

        //insert refresh token into database
        await userRefreshTokens.insert({userId: decodedRefreshToken.userId, refreshToken: newRefreshToken});

        //return response
        return res.status(200).json({accessToken, refreshToken: newRefreshToken});

    } catch (error) {
        //check if error is token expired or invalid
        if(error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({message: 'Invalid or expired refresh token'});
        }
        return res.status(500).json({message: error.message});
    }
});

//2fa generate route
app.get('/api/auth/2fa/generate', ensureAuthenticated, async (req, res) => {
    try {
        //check if 2fa is enabled
        const user = await users.findOne({_id: req.user.id});
        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, 'Optimasi.ai',secret);

        //update user with 2fa secret
        await users.update({_id:req.user.id}, {$set:{'2faSceret': secret}});
        await users.compactDatafile();

        //generate qr code
        const qrCode = await qrcode.toBuffer(uri, {type: 'image/png', margin: 1});

        //return response
        res.setHeader('Content-Disposition', 'attachment: filename=qrcode.png');
        return res.status(200).type('image/png').send(qrCode);
    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//2fa validate route
app.post('/api/auth/2fa/validate', ensureAuthenticated, async (req, res) => {
    try {
        //check if 2fa is enabled
        const { totp } = req.body;

        //check if totp is sent
        if(!totp) {
            res.status(422).json({message: 'TOTP is required'});
        }

        //check if 2fa is enabled
        const user = await users.findOne({_id: req.user.id});

        //check if 2fa is enabled
        const verified = authenticator.check(totp, user['2faSecret']);

        //return response
        if(!verified) {
            return res.status(400).json({message: 'TOTP is invalid or expired'});
        }

        //return response
        await users.update({_id: req.user.id}, {$set:{'2faEnable': true}});
        await users.compactDatafile();

        return res.status(200).json({message: '2FA enabled successfully'});
    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//logout route
app.get('/api/auth/logout',ensureAuthenticated, async (req, res) => {
    try { 

        //remove refresh token from database
        await userRefreshTokens.removeMany({ userId: req.user.id });
        await userRefreshTokens.compactDatafile();

        //insert access token into invalid token database
        await userInvalidToken.insert({accessToken: req.accessToken.value, userId: req.user.id, expirationTime: req.accessToken.exp});

        return res.status(204).json({message: "Content not found"});
    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//get current user route
app.get('/api/users/current', ensureAuthenticated, async (req, res) => {
    try {
        //get user from database
        const user = await users.findOne({_id: req.user.id});
        //return response
        return res.status(200).json({id: user._id, name: user.name, email: user.email});
    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

//admin routes
app.get('/api/admin', ensureAuthenticated, authorize(['admin']), (req, res) => {
    return res.status(200).json({message: 'Only admin can access this route'});
});

//moderator route
app.get('/api/moderator', ensureAuthenticated, authorize(['admin','moderator']), (req, res) => {
    return res.status(200).json({message: 'Only admin and moderator can access this route'});
});


//ensure authenticated middleware
async function ensureAuthenticated(req, res, next) {
    //check if access token is sent
    const accessToken = req.headers.authorization;
    //check if access token is valid
    if(!accessToken) {
        return res.status(401).json({message: 'Access token not found'});
    }
    //check if access token is in invalid token database
    if(await userInvalidToken.findOne({accessToken})) {
        return res.status(401).json({message: 'Access token invalid', code: "AccessTokenInvalid"});
    };
    try {
        //verify access token
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        //set user in request object
        req.accessToken = {value: accessToken, exp: decodedAccessToken.exp}
        req.user =  { id: decodedAccessToken.userId };
        //move to next middleware
        next();
    } catch (error) {
        //check if error is token expired or invalid
        if(error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({message: 'Access token in expired', code: "AccessTokenExpired"});
        } else if(error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message: 'Access token invalid', code: "AccessTokenInvalid"});
        } else {
            res.status(500).json({message: error.message});
        }
    }
};

//authorize authorize middleware
function authorize(roles = []) {
    //check if roles is an array
    return async function(req, res, next) {
        const user = await users.findOne({_id: req.user.id});

        //check if user exists and has the role
        if(!user || !roles.includes(user.role)) {
            return res.status(403).json({message: 'You are not authorized to access this route'});
        }

        //move to next middleware
        next();
    }
};


//running server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});