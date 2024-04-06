const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const validator = require('validator')

const Schema = mongoose.Schema

const userSchema = new Schema({
    email: { 
        type: String, 
        required: true,
        unique:true 
    },
    password: {
        type: String,
        required: true
    }
})

// static signup method
userSchema.statics.signup = async function(email, password) {
    // Check if email and password are provided
    if (!email ||!password) {
        throw Error('All fields must be filled')
    }

    // Validate email format
    if (!validator.isEmail(email)) {
        throw Error("Invalid email")
    }

    // Check if password is strong enough
    if (!validator.isStrongPassword(password)) {
        throw Error("Password not strong enough")
    }

    // Check if email already exists
    const exists = await this.findOne({ email })

    if (exists) {
        throw Error('Email already exists!')
    }

    // Generate salt and hash password
    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt)

    // Create new user
    const user = await this.create({email, password: hash })

    return user
}

// static login method
userSchema.statics.login = async function(email, password) { // Define function with email and password parameters

    if (!email ||!password) { // Check if email or password is missing
        throw Error('All fields must be filled') // Throw error if fields are missing
    }

    const user = await this.findOne({ email }) // Find user by email

    if (!user) { // Check if user exists
        throw Error('Incorrect email') // Throw error if email is incorrect
    }

    const match = await bcrypt.compare(password, user.password) // Compare input password with stored password

    if (!match) { // Check if passwords match
        throw Error ('Incorrect password') // Throw error if passwords don't match
    }

    return user // Return user if all checks pass

}

module.exports = mongoose.model('User', userSchema)