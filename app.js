// dependencies

const server = require('express')
const ejs = require('ejs')
const passport = require('passport')
const localPassort = require('passport-local')
const crypto = require('crypto')
const db = require("./data/db.json")
const { ifError } = require('assert')

// requiring the additional dependencies 

const logger = require('morgan')
const session = require('express-session')
const SDLiteStore = require('connect-sqlite3')(session)

// intializin app
const app =server()

// defining the hashedPassword
const saltRounds = 10

// setting the router 
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views')
app.use(server.json())
app.use(server.static(path.join(__dirname, 'public')))

//adding session support to the app and then authenticate the session.
app.use(session({
    secret : 'keyboard cat',
    resave :false,
    saveUninitialized : false,
    store : new SDLiteStore({db: 'sessions.db', dir:'./var/db'})
}))

app.use(passport.authenticate("session"))

// preventing encode url
app.use(server.urlencoded({extended: false}));

// setting the port
const port =4000
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log(`App is running on http://localhost:${port}`);
});

app.get('/', (req, res) => {
    res.render('index');
})

app.get('/login', (req, res) => {
    res.render('login');
})

// verifying password
passport.use(new localPassort(function verify(username, password, action){
    // finding the appropiate element in the table

const user = db.find(user => user.email === username)

if(err){return action(err)}
if(!user){return action(null, false, {message : 'wrong username or passwords'}
)}

crypto.pbkdf2(password, user.password,310000, saltRounds,'sha256', function(err, hashedPassword){

    if (err) {return action(err)}
      if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
        return action(null, false, {message : 'wrong username or passwords'})
      }  
    return action(null, user)
})
}))

passport.serializeUser(function(user, action){
    process.nextTick(function(){

        action(null, {id:user.id, username: user.username})
    })
})
assport.deserializeUser(function(user, action){
    process.nextTick(function(){

        action(null,user)
    })
})


app.post('/login/password', passport.authenticate('local',{
    successRedirect : '/',
    failureRedirect : '/login'
}))

// establish session


