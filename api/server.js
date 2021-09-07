const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());
require("dotenv").config();
const cert = process.env.SECRET_KEY;
const refreshCert = process.env.REFRESH_SECRET_KEY;

const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
  // Take the refresh token from the user
  const refreshToken = req.body.token;

  // Send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated!");
  if (!refreshTokens.includes(refreshToken))
    return res.status(403).json("Refresh token is not valid!");

  jwt.verify(refreshToken, refreshCert, (err, decoded) => {
    err && console.log(err);

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(decoded);
    const newRefreshToken = generateRefreshToken(decoded);
    refreshTokens.push(newRefreshToken);

    return res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  // if everything is ok, create new access token, refresh token and send user
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, cert, {
    expiresIn: "15m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, refreshCert);
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    // Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    return res.status(200).json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    return res.status(400).json("error");
  }
});

// middleware
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1]; // take token, not Bearer
    jwt.verify(token, cert, (err, decoded) => {
      // decoded or payload
      if (err) {
        return res.status(403).json("Token is not valid!");
      }
      req.user = decoded;
      return next(); // callback
    });
  } else {
    return res.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    return res.status(200).json("User has been deleted.");
  } else {
    return res.status(403).json("You are not allowed to delete this user!");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  return res.status(200).json("You logged out successfully.");
});

module.exports = app;
