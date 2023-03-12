const mongoose = require('mongoose')
const validator = require('validator')  
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const Task = require('./task')

const userSchema = mongoose.Schema({
    name: {
        type: String
    },
    age: {
        type: Number,
    },
    password: {
        type: String,
        required: true,
        trim: true,
        minlength: 7,
        validate(value) {
            if (value.toLowerCase().includes('password'))
                throw new Error('Error! password can not contain "password"')
        }
    },
    email: {
        type: String,
        unique: true,
        required: true,
        validate(value) {
            if (!validator.isEmail(value))
                throw new Error('invalid email')
        }
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }],
    avatar: {
        type: Buffer
    }
}, {
    timestamps: true
})

userSchema.virtual('tasks', {
    ref: 'Task',
    localField: '_id',
    foreignField: 'owner'
})

userSchema.methods.generateAuthToken = async function () {

    const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET)

    this.tokens.push({ token })
    await this.save()

    return token
}

userSchema.methods.toJSON = function () {
    const user = this

    const userObject = user.toObject()

    delete userObject.password
    delete userObject.tokens
    delete userObject.avatar

    return userObject
}

userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({email})
    

    if (!user)
        throw new Error()
    
    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch)
        throw new Error()

    return user
}

userSchema.pre('save', async function (next) {
    
    if (this.isModified('password'))
        this.password = await bcrypt.hash(this.password, 8)

    next()
})

userSchema.pre('remove', async function (next) {
    const user = this

    await Task.deleteMany({ owner: user._id })
    next()
})

const User = mongoose.model('User', userSchema)

module.exports = User
