const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const User = new Schema ({
    email:String,
    password:String,
    name:String
});

const Usermodel = mongoose.model('user',User);

module.exports = {
    Usermodel
}
