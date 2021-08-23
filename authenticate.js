const express = require("express")
const bodyParser = require("body-parser")
const bcrypt = require("bcrypt")
const { v4: uuid } = require("uuid")
const jwt = require('jsonwebtoken');
const SALT_ROUNDS = 10
const JWT_SECRET = 'shhhhhh'

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
  //token
  if (token) {
    try {
      const { id: userId, passwordUpdatedAt } = jwt.verify(token, JWT_SECRET)
      const user = users.find(u => {
        
        return u.id === userId && u.passwordUpdatedAt === passwordUpdatedAt
      })
      if (!user) {
        return false
      }
      return redactUserInfo(user)
    } catch (e) {
      console.log(e)
      return false
    }
  }

  // password auth
  const user = users.find(u => u.username === username)
  if (!user) {
    return false
  }

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







app.listen(3000, () => {
  console.log('App listening at http://localhost:3000')
})
