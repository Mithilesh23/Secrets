require('dotenv').config();
const express=require("express");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
var findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app=express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(express.urlencoded({extended:true}));

app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false
})
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true});
mongoose.set("useCreateIndex",true);

const userSchema=new mongoose.Schema(
    {email:String,
    password:String,
    googleId:String,
    secret:String
   });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

 

const User=new mongoose.model("User",userSchema);
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user,done){
    done(null,user.id);
});
passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




app.get("/",function(req,res){
    res.render("home");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/secrets",function(req,res){
     User.find({secret:{$ne:null}},function(err,foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets",{userWithSecrets:foundUsers});
            }
        }
     });
});

app.get("/logout",function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }
        res.redirect("/");
    });
   
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
  );

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;
     console.log(req.user.id);

     User.findById(req.user.id,function(err,foundUser){
            if(err){
                console.log(err);
            }
            else{
                if(foundUser){
                    foundUser.secret=submittedSecret;
                    foundUser.save(function(){
                        res.redirect("/secrets");
                    });
                }
            }
     });

});



app.post("/register",function(req,res){
    
//.register method from passportlocalMongoose which will take care of creating new user and saving user,we can 
//directly interact with our database module..

User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
        console.log(err);
        res.redirect("/register");
    }
    else{
        passport.authenticate("local")(req,res,function(){
           res.redirect("/secrets");
        });
    }
});
    

   
});

app.post("/login",function(req,res){
   const user=new User({
    username:req.body.username,
    password:req.body.password
   });
   req.login(user,function(err){
    if(err){
        console.log(err);
    }
    else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        });
    }
   })
           
           
});






app.listen(3000,function(req,res){
    console.log("Listening on port 3000");
})
