require('dotenv').config()
const config = {
  mongoUrl: process.env.MONGO_URL,
}

const MongoClient = require('mongodb').MongoClient;
const express = require("express")
const assert = require('assert');
const bodyParser = require("body-parser")
const bcrypt = require("bcrypt")
const { v4: uuid } = require("uuid")
const jwt = require('jsonwebtoken');


const SALT_ROUNDS = 10
const JWT_SECRET = 'donttellanyone'

const app = express()
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(bodyParser.raw())

const users = []

function redactUserInfo(user) {
  user = { ...user }
  delete user.hashedPassword
  delete user.passwordUpdatedAt
  return user
}

//Authenticate user using username and password or token. 
async function authUser({ username, password, token }) {

  const users = db.collection('users');
  //token
  if (token) {
    try {
      const tokenValue = jwt.verify(token, JWT_SECRET)
      const user = await users.findOne({ username: tokenValue.username })
      return user ? redactUserInfo(user) : false
    } catch(e) {
      console.log(e)
      return false
    }
  }

  // user auth
  const user = users.find(u => u.username === username)
  if (!user) {
    return false
  }

  //password auth
  const passwordMatches = await bcrypt.compare(password, user.hashedPassword)
  if (!passwordMatches) {
    return false
  }

  // return redacted user with new token
  return {
    ...redactUserInfo(user),
    token: getAuthToken(user)
  }
}

//new auth
function getAuthToken(user) {
  return jwt.sign({
    id: user.id,
    passwordUpdatedAt: user.passwordUpdatedAt
  }, JWT_SECRET, { expiresIn: '1h' });
}

//  Connect to Mongo DB client
let db;
const client = new MongoClient(config.mongoUrl, { useUnifiedTopology: true });
// Use connect method to connect to the server
client.connect(function(err) {
  assert.strictEqual(null, err);
  db = client.db('twitter');

  // setup users
  const users = db.collection('users')
  users.createIndex( { username: 1 }, { unique: true } )

  app.emit('db-connected')
});

/**
 * updateUserPassword
 */
async function updateUserPassword(user, password) {
  user.hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)
  user.passwordUpdatedAt = Date.now()
}

//middleware
async function authMiddleware(req, res, next) {
  const { username, password } = req.body
  const { authorization } = req.headers
  const token = authorization?.replace(/^Bearer\s/,'')

  const user = await authUser({ username, password, token })
  if (!user) {
    res.status(401).send({
      error: 'incorrect username or password' // FIX THIS
    })
    return
  }

  req.user = user
  next()
}

/**
 * Signup using username and password
 */
app.post('/signup', async (req, res) => {
  const { username, password } = req.body

  // check if user exsists
  const userConflict = users.find(u => u.username === username)
  if (userConflict !== undefined) {
    res.status(400).send({
      error: `Username "${username}" is taken`
    })
    return
  }

  // create and save user
  const user = {
    id: uuid(),
    username
  }
  await updateUserPassword(user, password)
  users.push(user)

  // return auth token
  res.send(redactUserInfo(user))
})

/**
 * Authenticate using username and password then return auth token
 */
app.post('/login', authMiddleware, (req, res) => {
  // return auth token
  res.send({
    user: req.user
  })
})

/**
 * Example authenticated endpoint
 */
app.get('/auth', authMiddleware, (req, res) => {
  // return user used for auth
  res.send({
    test: 'test'
  })
})


app.post('/order', authMiddleware, async (req, res) => {
  const { price } = req.body.price
  const { message } = req.body.message
  const { username } = req.user

  if (message === undefined) {
    res.status(400).send({
      error: 'message and handle required.'
    })
    return
  }

  if (message.length < 10 || message.length > 800) {
    res.status(400).send({
      error: 'Description should be between 10 to 800 characters.'
    })
    return
  }

  const orders = db.collection('orders') 

  const order = await order.insertOne({
    price,
    message,
    username
  })

  res.send(order.ops)
})

app.get('/orders', async (req, res) => {
  const orders = db.collection('orders') 
  const data = await orders.find().sort({_id: -1})
  res.send(await data.toArray())
})

app.on('db-connected', () => {
  helpers.ifPortIsFree(config.port, () => {
    app.listen(config.port, () => {
      console.log(`app listening on http://localhost:${config.port}`)
    })
  })
})





app.listen(3000, () => {
  console.log('App listening at http://localhost:3000')
})