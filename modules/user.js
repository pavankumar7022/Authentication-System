const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

// hash password before save
userSchema.pre('save', async function(next) {
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// compare password
userSchema.methods.comparePassword = function(password) {
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);