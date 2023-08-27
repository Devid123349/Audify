require("dotenv").config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require("express-session");
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;
var MicrosoftStrategy = require('passport-microsoft').Strategy;
const extractAudio = require('ffmpeg-extract-audio')
// const ffmpeg = require('fluent-ffmpeg');
const download = require('download');
const multer = require('multer');
// const { MongoClient } = require('mongodb');
const ffmpeg = require('fluent-ffmpeg');
const { Readable } = require('stream');
const { MongoClient, ObjectId } = require('mongodb');
const fs = require('fs');

const app = express();

// Set up the storage engine for multer 
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb+srv://admin-chaitanya:Test123@cluster0.upazi.mongodb.net/audify?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  microsoftId: String
});
const audioSchema = new mongoose.Schema({
  name: String,
  video: Buffer,
  audio: Buffer
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
audioSchema.plugin(passportLocalMongoose);
audioSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
const Audio = new mongoose.model("Audio", audioSchema);

passport.use(User.createStrategy());
passport.use(Audio.createStrategy());

passport.serializeUser(function (user, done) {
  //user.id is not profile id. it is id that created by the database
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      facebookId: profile.id
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new MicrosoftStrategy({
  // Standard OAuth2 options
  clientID: process.env.MICROSOFT_CLIENT_ID,
  clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/microsoft/secrets",
  scope: ['user.read'],

  // Microsoft specific options

  // [Optional] The tenant for the application. Defaults to 'common'.
  // Used to construct the authorizationURL and tokenURL
  tenant: 'common',

  // [Optional] The authorization URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`
  authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',

  // [Optional] The token URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`
  tokenURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
},
  function (accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({
      userId: profile.id
    }, function (err, user) {
      return done(err, user);
    });
  }
));



app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"],
    prompt: 'select_account',
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/microsoft',
  passport.authenticate('microsoft', {
    // Optionally define any authentication parameters here
    // For example, the ones in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    prompt: 'select_account',
  }));

app.get('/auth/microsoft/secrets',
  passport.authenticate('microsoft', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function (req, res) {
  res.render("login");
});
app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/register", function (req, res) {
  res.render("register");
});
app.post("/register", function (req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function (err, user) {
    if (err) {
      console.log(err);
    } else {
      if (user) {
        user.secret = submittedSecret;
        user.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/secrets", function (req, res) {
  User.find({
    "secret": {
      $ne: null
    }
  }, function (err, users) {
    if (err) {
      console.log(err);
    } else {
      if (users) {
        res.render("secrets", {
          converted: false
        });
      }
    }
  });
});

// upload.single('videofile')
app.post("/upload", upload.single('videofile'), function (req, res) {
  const file = req.file.buffer;
  const fileName = req.file.originalname;
  // Example usage
  var videoId; // Replace with the ID of the video file stored in MongoDB

  Audio.findOrCreate({
    name: fileName,
    video: file
  }, function (err, res) {
    if (err) {
      console.log(err);
    } else {
      videoId = res.id;
      console.log('File uploaded to MongoDB!', videoId);
    }
  });
  // Audio.findOne({ name: fileName }, function (err, user) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (file) {

  //       // file.save();
  //     }
  //   }
  // });
  const uri = 'mongodb+srv://admin-chaitanya:Test123@cluster0.upazi.mongodb.net/audify?retryWrites=true&w=majority'; // MongoDB connection URI
  const dbName = 'audify'; // Name of your MongoDB database
  // Collection name where the video file is stored
  const collectionName = 'audios';

  const client = new MongoClient(uri);

  async function connect() {
    try {
      await client.connect();
      console.log('Connected to MongoDB');
    } catch (error) {
      console.error('Error connecting to MongoDB:', error);
    }
  }
  connect();

  async function convertVideoToAudio(videoId) {
    try {
      // Get the video document from MongoDB
      const db = client.db(dbName);
      const collection = db.collection(collectionName);
      const video = await collection.findOne({ _id: videoId });

      // Generate a unique filename for the audio file
      const audioFilename = `audio_${videoId}.mp3`;

      // Convert the video to audio using FFmpeg
      ffmpeg(video.filePath)
        .output(audioFilename)
        .on('end', async () => {
          // Read the converted audio file
          const audioFileData = await fs.promises.readFile(audioFilename);

          // Update the video document with the audio file data
          await collection.updateOne(
            { _id: videoId },
            {
              $set: {
                audio: audioFileData,
                name: audioFilename
              }
            }
          );

          // Save the audio file on your device
          await fs.promises.writeFile(audioFilename, audioFileData);

          console.log('Video converted to audio and saved successfully.');
        })
        .on('error', (error) => {
          console.error('Error converting video to audio:', error);
        })
        .run();
    } catch (error) {
      console.error('Error converting video to audio:', error);
    }
  }
  convertVideoToAudio(videoId);

});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});



app.listen(process.env.PORT || 3000, function () {
  console.log('Server started on port 3000.');
});
