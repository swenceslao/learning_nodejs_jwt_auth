const express = require('express')
const app = express()
const dotenv = require('dotenv')
const mongoose = require('mongoose')

dotenv.config()

// Import routes
const authRoute = require('./routes/auth')
const postRoute = require('./routes/posts')

// Connect to mongodb
mongoose.connect(
  process.env.DB_CONNECT, 
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => console.log('Connected to mongoDB!'))

// Middleware
app.use(express.json())

// Route middleware
app.use('/api/user', authRoute)
app.use('/api/posts', postRoute)

app.listen(3000, () => console.log('Server running'))