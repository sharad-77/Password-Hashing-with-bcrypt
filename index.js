const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const z = require("zod");
const { Usermodel } = require("./db");
require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;


const dataBase = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URL, {
      connectTimeoutMS: 30000,
      socketTimeoutMS: 30000,
    });
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
    process.exit(1); // Exit the process on connection failure
  }
};

dataBase();

const jwt_secret = process.env.JWT_SECRET;

const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;

    const validtion = z.object({
      email: z.string().min(3).max(50).email(),
      password: z.string().min(2).max(34),
      name: z.string().min(2).max(34)
    });

    const parsedData = validtion.safeParse(req.body);

    if (!parsedData.success) {
      return res.status(400).json({
        message: "Please enter data in the correct format",
        errors: parsedData.error.errors, 
      });
    }
    const hasedPassword = await bcrypt.hash(password, 5);
    console.log(hasedPassword);

    const user = await Usermodel.create({
      email: email,
      password: hasedPassword,
      name: name,
    });

    res.json({
      message: "You signed up successfully",
    });
});

app.post("/signin", async (req,res) => {

    const email = req.body.email;
    const password = req.body.password;

    const respons = await Usermodel.findOne({
        email:email
    })
    const comparesPassword = await bcrypt.compare(password,respons.password);
    if (comparesPassword){
        const token = jwt.sign({
            email:email
        },JWT_SECRET);

        console.log(JWT_SECRET);

        res.json({
            token:token
        })
    }
    res.json({
        message:"You signin"
    })
})

app.listen(3000);
