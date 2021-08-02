const express = require('express')
const bodyParser = require('body-parser')

const app = express()

app.listen(3000, () => {
    console.log('App listening at http://localhost:3000')
})