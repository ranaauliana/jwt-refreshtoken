const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("./models/userModel");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
require("dotenv").config();

const PORT = 5000;
const app = express();
app.use(express.json());

// middleware
function auth(req, res, next) {
  const header = req.headers["authorization"];
  //   console.log(`header: ${header}`);

  // ambil tokennya dari headers
  const token = header && header.split(" ")[1];

  // err token
  if (token == null) return res.sendStatus(401);

  //verify token
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    // definisi user
    req.user = user;
    next();
  });
}

// refresh token
app.post("/token", async (req, res) => {
  // ambil token dari body
  const refreshToken = req.body.token;
  // query refresh token dari db
  const dbToken = await User.findOne({ refreshTokens: refreshToken });

  // refreshtoken from body doesn't exist
  if (refreshToken == null) return res.sendStatus(401);
  // token db doesn't exist
  if (!dbToken) return res.sendStatus(403);
  /////// if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  // verify refresh token untuk membuat token baru
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    // membuat token baru
    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken: accessToken });
  });
});

// route home
app.get("/", auth, (req, res) => {
  res.send("hei");
});

// menghapus refresh token dari db
app.post("/logout", async (req, res) => {
  // mengambil token dari body
  const token = req.body.token;
  // query refresh token dari db
  const userToken = await User.findOne({ refreshTokens: token });

  // err refreshtoken db doesn't exist
  if (!userToken) return res.sendStatus(404);

  // update data db and delete token
  await User.findOneAndUpdate(
    { _id: userToken._id },
    { $unset: { refreshTokens: 1 } },
    false,
    true
  );

  // refreshTokens = await User.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

// register account
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // query username if already exist
  const acc = await User.findOne({ username: username });
  // error if it does
  if (acc) return res.sendStatus(403);

  const user = new User({
    username: username,
    password: bcrypt.hashSync(password, 10),
  });

  await user.save();
  res.json({ user: user });
});

// login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const acc = await User.findOne({ username: username });

  if (!acc) return res.sendStatus(404);

  // cek password
  const checkPassword = await bcrypt.compare(password, acc.password);

  if (!checkPassword) return res.sendStatus(403);

  const user = {
    username: username,
    password: acc.password,
  };

  // deklarasi token user
  const accessToken = generateAccessToken(user);
  // deklarasi refresh token user dan simpan dalam db
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN);
  await User.findOneAndUpdate(
    { username: username },
    { refreshTokens: refreshToken }
  );

  res.json({ token: accessToken, refreshToken: refreshToken });
});

// token
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: "30s" });
}

// database connetion
mongoose.connect("mongodb://127.0.0.1:27017/dbauth").then(() =>
  //   {
  //     const db = mongoose.connection.db;
  //     db.collection("users").insertOne({ username: "puririn" });
  //   }
  console.log("Connected!")
);

app.listen(PORT, () => {
  console.log(`listen on port : ${PORT}`);
});
