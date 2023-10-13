const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs")
require("dotenv").config()

const mongoDb = process.env.MONGODB_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username or password" });
      };

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password or username" })
      }
      // if (user.password !== password) {
      //   return done(null, false, { message: "Incorrect password" });
      // };
      return done(null, user);
    } catch(err) {
      return done(err);
    };
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  };
});

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => res.render("index", { user: req.user }));
app.get("/signup", (req, res) => res.render("signup"));
app.get("/login", (req, res) => res.render("login"));



app.post("/signup", async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
    if(err) {
      throw new Error(500)
    }
    // if err, do something
    // otherwise, store hashedPassword in DB
    try {
      const user = new User({
        username: req.body.username,
        password: hashedPassword
      });
      const result = await user.save();
      console.log(result);
      res.redirect("/");
    } catch(err) {
      return next(err);
    };
  })  
});



// app.post("/signup", async (req, res, next) => {
  
//   try {
//     const user = new User({
//       username: req.body.username,
//       password: req.body.password
//     });
//     const result = await user.save();
//     console.log(result);
//     res.redirect("/");
//   } catch(err) {
//     return next(err);
//   };
// });

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
  })
);

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));