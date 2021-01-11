const express = require('express')
const app = express()
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const dbURL = 'mongodb+srv://<username>:<password>@cluster0.hy7dn.mongodb.net/<dbname>?retryWrites=true&w=majority'
const userModel = require('./Model/users')
const key = 'password'
const algo = 'aes256'
const jwtKey = 'jwt'

mongoose.connect(dbURL, {useUnifiedTopology: true, useNewUrlParser: true})
    .then(() => console.log('connected'))

app.get('/', (request, response) => {
    response.end('hello')
})

app.post('/register', jsonParser, (request, response) => {
    const cipher = crypto.createCipher(algo, key)
    const encryptedPassword = cipher.update(request.body.password, 'utf8', 'hex') + cipher.final('hex')

    const data = new userModel({
        _id: new mongoose.Types.ObjectId,
        name: request.body.name,
        email: request.body.email,
        password: encryptedPassword
    })

    data.save()
        .then((result) => {
            jwt.sign({result}, jwtKey, {expiresIn: '300s'}, (err, token) => {
                response.status(201).json({token})
            })
        })
        .catch((err) => {
            console.log(err)
        })

})

app.post('/login', jsonParser, (request, response) => {
    userModel.findOne({email: request.body.email})
        .then(result => {
            const deCipher = crypto.createDecipher(algo, key)
            const deCryptedPassword = deCipher.update(result.password, 'hex', 'utf8') + deCipher.final('utf8')
            if (deCryptedPassword === request.body.password) {
                jwt.sign({result}, jwtKey, {expiresIn: '300s'}, (err, token) => {
                    response.status(200).json({token})
                })
            } else {
                response.end('Something went wrong. Please check your password and email')
            }
        })
})

app.get('/users', userValidityCheck, (request, response) => {
    userModel.find()
        .then(data => {
            response.status(200).json(data)
        })
})

function userValidityCheck(request, response, next) {
    const bearerHeader = request.headers['authorization']

    if (typeof bearerHeader !== 'undefined') {

        request.token = bearerHeader.split(' ')[1]

        jwt.verify(request.token, jwtKey, (err, authData) => {
            if (err) response.json({result: err})
            else next()
        })
    } else {
        response.send({'result': 'Token not provided'})
    }
}

app.listen(5050)
