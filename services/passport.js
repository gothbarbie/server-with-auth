const passport = require('passport')
const User = require('../models/user')
const config = require('../config')

const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Local Strategy
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {

  // Verify username and password
  User.findOne({ email: email }, function (err, user) {
    if (err) { return done(err) }
    if (!user) { return done(null, false) }

    // compare passwords
    user.comparePassword(password, function (err, isMatch) {
      if (err) { return done(err) }
      if (!isMatch) { return done(null, false) }

      return done(null, user)
    })
  })
})


// JWT Strategy
// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}
const jwtLogin = new JwtStrategy(jwtOptions, function (payload, done) {

  // See if user ID exists in database
  User.findById(payload.sub, function (err, user) {
    if (err) { return done(err, false) }

    if (user) {
      done(null, user)
    }
    done(null, false)
  })
})

// Tell passport to use it
passport.use(jwtLogin)
passport.use(localLogin)
