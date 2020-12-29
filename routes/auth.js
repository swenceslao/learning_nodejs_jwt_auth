const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../model/User')
const { registerValidation, loginValidation } = require('../validation')

router.post('/register', async (req, res) => {
  try {
    // Validate first
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details)

    // Check if user already exists
    const emailExist = await User.findOne({ email: req.body.email })
    if (emailExist) return res.status(400).send('Email already exists') 

    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10)

    // Create a new user
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    })

    const savedUser = await user.save()
    res.status(200).send({
      status: 200,
      message: 'success',
      data: savedUser,
    })  

  } catch (error) {
    res.status(500).send({
      status: 500,
      message: 'Something went wrong when processing the request.',
      error: error
    })

  }
})

router.post('/login', async (req, res) => {
  try {
     // Validate first
     const { error } = loginValidation(req.body)
     if (error) return res.status(400).send(error.details)
 
     // Check if email exist
     const user = await User.findOne({ email: req.body.email })
     if (!user) return res.status(400).send('Email address does not exist')
     
     // Check if password is correct
     const validPassword = await bcrypt.compare(req.body.password, user.password)
     if (!validPassword) return res.status(400).send('Invalid password')

     // Create and assign a token
     const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET)
     res.header('auth-token', token).send(token)

    //  res.status(200).send({
    //    status: 200,
    //    message: 'Log in success',
    //    data: user,
    //  })

  } catch (error) {
    res.status(500).send({
      status: 500,
      message: 'Something went wrong when processing the request.',
      error: error
    })

  }
})

module.exports = router