const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, index: true },
    password_hash: { type: String, required: true },
    display_name: { type: String, default: '' },
    email: { type: String, default: '' },
    must_change_password: { type: Boolean, default: false },
    last_login_at: { type: Date, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);
