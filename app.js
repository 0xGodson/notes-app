// Imports
const express = require('express');
const jwt = require('jsonwebtoken')
const crypto = require('crypto');
const RequestIp = require('@supercharge/request-ip');
const {v4: uuidv4} = require('uuid');
const jsdom = require('jsdom');
const path = require('path');
const createDOMPurify = require('dompurify');
const cookieParser = require('cookie-parser');
require('ejs');

// Setup
const jwtSecret = crypto.randomBytes(20).toString('hex')
const {JSDOM} = jsdom;
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const app = express()

// MiddleWare
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.set('view engine', 'ejs')
app.use('/challenge', express.static('./static'))

// Database
const db = Object.create(null);
db.users = Object.create(null);
db.nonces = Object.create(null);

// Globals
let currentUser;
let userIP;

// Verify if the User is Authenticated!
isAuthed = async (req, res, next) => {
    let headers = req.headers;
    for (let i in headers) {
        if (i.toLowerCase().includes('x-') || i.toLowerCase().includes('ip') || i.toLowerCase().includes('for')) {
            if (i.toLowerCase() !== 'x-real-ip') { // nginx configuration
                delete req.headers[i];
            }
        }
    }

    if (!req.headers['cookie']) return res.redirect('/challenge/auth');

    try {
        const authToken = req.cookies['jwt'];
        jwt.verify(authToken, jwtSecret, {}, (err, user) => {
            if (err) return res.redirect('/challenge/auth')

            if (user && db.users[user.user]) {
                currentUser = user.user;
                userIP = RequestIp.getClientIp(req);
                next();
            } else {
                res.redirect('/challenge/auth?alert=user not found');
            }
        })
    } catch (e) {
        res.redirect('/challenge/begin?alert=Something Went Wrong!');
    }
}

// no xss :)

function noscript(text) {
    matches = text.toLowerCase().match(/(script)|(nonce)|(href)|(getsecret)|(ip-secret)|(form)|(input)|(nonce)/)
    if(matches === null){
        return text
    }else{
        return "[NO XSS]"
    }
}



app.get('/',  (req, res) => {
    res.sendFile(path.join(__dirname, './static', 'start.html'));
})

app.get('/favicon.ico',  (req, res) => {
    res.sendFile(path.join(__dirname, './static', 'favicon.ico'));
})

app.get('/challenge/getSecret.js',  isAuthed, (req, res) => {
    try {
        if (db.users[currentUser]['ip'] !== userIP) {
            return res.redirect('/challenge/auth?alert=Illegal Access!');
        }
        const script = `
    /* Only Share the Secret if the Host is Trusted! */
    if (window.saveSecret) {
      if (document.domain === 'challenge-1022.intigriti.io' && window.location.href === 'https://challenge-1022.intigriti.io/challenge/create') {
        console.log('secret Sent!');
        window.saveSecret('${db.users[currentUser]['secret']}');
      }
    }
    `
        res.setHeader('content-type', 'text/javascript');
        res.send(script);
    } catch {
        res.send('Something Went Wrong');
    }

})

app.get('/challenge/auth',  (req, res) => {
    res.setHeader('Content-Security-Policy', `script-src 'self';base-uri 'self';  style-src 'self' 'unsafe-inline'; img-src *;default-src 'none';object-src 'none';`);
    res.render('auth');
})

app.post('/challenge/auth',  (req, res) => {
    try {
        delete req.headers['x-forwarded-for'];
        delete req.headers['x-client-ip'];
        const headers = req.headers;
        for (let i in headers) {
            if (i.toLowerCase().includes('x-') || i.toLowerCase().includes('ip') || i.toLowerCase().includes('-for')) {
                if (i.toLowerCase() !== 'x-real-ip') {
                    delete req.headers[i];
                }
            }
        }
        
        if (!req.body.username || !req.body.password) {
            return res.redirect('/challenge/auth?message=username or password is empty');
        }
        if (db.users[req.body.username] && db.users[req.body.username].password === req.body.password) {
            if (db.users[req.body.username]['ip'] === RequestIp.getClientIp(req)) {
                const authToken = jwt.sign({user: req.body.username}, jwtSecret)
                res.setHeader('Set-Cookie', [`jwt=${authToken}; HttpOnly; secure; SameSite=Strict`]);
                return res.redirect('/challenge/begin?message=Login Success! NOTE: WE FIXED A UNINTENDED SOLUTION NOW AND THE NEW CODE IS UPDATED IN THE GITHUB REPO ASWELL!');
            } else {
                return res.redirect('/challenge/auth?alert=Illegal Access!');
            }

        }
        if (db.users[req.body.username] && db.users[req.body.username].password !== req.body.password) {
            return res.redirect('/challenge/auth?alert=Password Wrong!');
        }
        if (!db.nonces[RequestIp.getClientIp(req)]) {
            db.nonces[RequestIp.getClientIp(req)] = crypto.randomBytes(20).toString('hex');
        }
        db.users[req.body.username] = Object.create(null);
        db.users[req.body.username]['password'] = req.body.password;
        db.users[req.body.username]['ip'] = RequestIp.getClientIp(req);
        db.users[req.body.username]['secret'] = crypto.randomBytes(20).toString('hex');
        const authToken = jwt.sign({user: req.body.username}, jwtSecret);
        db.users[req.body.username].posts = [];
        res.setHeader('Set-Cookie', [`jwt=${authToken}; HttpOnly; secure; SameSite=Strict`]);
        res.redirect('/challenge/begin?message=Account Created! NOTE: WE FIXED A UNINTENDED SOLUTION NOW AND THE NEW CODE IS UPDATED IN THE GITHUB REPO ASWELL!');
    } catch {
        res.redirect('/challenge/begin?alert=Something went Wrong');
    }
})


app.get('/challenge/begin',  isAuthed, (req, res) => {

    try {
        res.setHeader('Content-Security-Policy', `script-src 'self';base-uri 'self';  style-src 'self' 'unsafe-inline'; img-src *;default-src 'none';object-src 'none';`);
        if (db.users[currentUser]['ip'] !== userIP) {
            return res.redirect('/challenge/auth?alert=Illegal Access!');
        }
        const posts = db.users[currentUser].posts;
        if (posts.length > 0) {
            const titles = [];
            for (let i in posts) {
                titles.push(db.users[currentUser][posts[i]]['title']);
            }
            return res.render('index', {user: noscript(currentUser), notes: titles, uuid: posts});
        } else {
            res.render('index', {user: noscript(currentUser)});
        }
    } catch (e) {
        res.redirect('/challenge/begin?alert=Something went Wrong');
    }
});

app.get('/challenge/create',  isAuthed, (req, res) => {
    try {
        res.setHeader('Content-Security-Policy', `script-src 'self';base-uri 'self';  style-src 'self' 'unsafe-inline'; img-src *;default-src 'none';object-src 'none';`);
        if (db.users[currentUser]['ip'] !== userIP) {
            return res.redirect('/challenge/auth?alert=Illegal Access!');
        }
        res.render('note', {user: noscript(currentUser)});
    } catch {
        res.redirect('/challenge/begin?alert=Something went Wrong');
    }
});

app.post('/challenge/add',  isAuthed, (req, res) => {
    try {
        if (db.users[currentUser]['ip'] !== userIP) {
            return res.redirect('/challenge/auth?alert=Illegal Access!');
        }
        try {
            if (!req.body.body || !req.body.title) {
                return res.redirect('/challenge/create');
            } else {
                if (!req.body.secret) {
                    return res.redirect('/challenge/auth?alert=something went Wrong!');
                }
                if (req.body.secret === db.users[currentUser]['secret']) {
                    const title = DOMPurify.sanitize(req.body.title, {FORBID_TAGS: ['style']});
                    const body = DOMPurify.sanitize(req.body.body, {FORBID_TAGS: ['style']});
                    const uuid = uuidv4();
                    db.users[currentUser].posts.push(uuid);
                    db.users[currentUser][uuid] = Object.create(null);
                    db.users[currentUser][uuid].title = title;
                    db.users[currentUser][uuid].body = body;
                    res.redirect('/challenge/begin');
                } else {
                    return res.redirect('/challenge/auth?alert=something went Wrong!');
                }
            }
        } catch (e) {
            console.log(e);
            res.redirect('/challenge/add?alert=Something Went Wrong');
        }
    } catch (e) {
        console.log(e);
        res.redirect('/challenge/begin?alert=Something went Wrong');
    }
})

app.get('/challenge/view/:uuid',  isAuthed, (req, res) => {

    try {
        if (db.users[currentUser]['ip'] !== userIP) {
            return res.redirect('/challenge/auth?alert=Illegal Access!');
        }
        let uuid = req.params.uuid;

        const posts = db.users[currentUser].posts;
        if (!posts.includes(uuid)) {
            return res.redirect('/challenge/begin?alert=Note not Found!');
        }
        res.setHeader('Content-Security-Policy', `script-src 'nonce-${db.nonces[RequestIp.getClientIp(req)]}';base-uri 'self';  style-src 'self' 'unsafe-inline'; img-src *;default-src 'none';object-src 'none';`)
        res.render('view', {
            title: db.users[currentUser][uuid]['title'],
            body: db.users[currentUser][uuid]['body'],
            user: noscript(currentUser),
            nonce: db.nonces[db.users[currentUser]['ip']]
        })
    } catch {
        res.redirect('/challenge/begin?alert=Something went Wrong');
    }
});

app.get('/challenge/theme',  isAuthed, (req, res) => {
    try {
        if (db.users[currentUser].ip !== '127.0.0.1') {
            res.redirect('/challenge/begin?alert=Themes Under Construction');
        }

        function replaceSlash(str) {
            return str.replaceAll('\\', '');
        }

        if (req.query.callback) {
            if (/^[A-Za-z0-9_.]+$/.test(req.query.callback)) {
                if (req.query.backgroundTheme && req.query.colorTheme) {
                    if (/^[#][0-9a-z]{6}$/.test(req.query.backgroundTheme) && /^[#][0-9a-z]{6}$/.test(req.query.colorTheme)) {
                        return res.render('theme', {
                            theme: {
                                callback: req.query.callback,
                                background: replaceSlash(req.query.backgroundTheme),
                                font: replaceSlash(req.query.colorTheme)
                            }
                        })
                    } else {
                        return res.render('theme', {theme: false})
                    }
                }
                if (req.query.backgroundTheme) {
                    if (/^[#][0-9a-z]{6}$/.test(req.query.backgroundTheme)) {
                        return res.render('theme', {
                            theme: {
                                callback: req.query.callback,
                                background: replaceSlash(req.query.backgroundTheme)
                            }
                        })
                    } else {
                        return res.render('theme', {theme: false})
                    }
                }
                if (req.query.colorTheme) {
                    if (/^[#][0-9a-z]{6}$/.test(req.query.colorTheme)) {
                        return res.render('theme', {
                            theme: {
                                callback: req.query.callback,
                                font: replaceSlash(req.query.colorTheme)
                            }
                        })
                    } else {
                        return res.render('theme', {theme: false})
                    }
                }
            }
        } else {
            return res.render('theme', {theme: false})
        }
    } catch {
        res.redirect('/challenge/begin?alert=Something went Wrong')
    }
})

app.listen(80);
