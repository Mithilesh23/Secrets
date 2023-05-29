require('dotenv').config();
const express=require("express");
const ejs=require("ejs");
const mongoose=require("mongoose");
const bcrypt=require("bcrypt");
const saltRounds=10;
const app=express();

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true});

const userSchema=new mongoose.Schema(
    {email:String,
    password:String
   });

 

const User=new mongoose.model("User",userSchema);
app.use(express.static("public"));
app.set("view engine","ejs");
app.use(express.urlencoded({extended:true}));

app.get("/",function(req,res){
    res.render("home");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.post("/register",function(req,res){
    
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser=new User({
            email:req.body.username,
            password:hash
        });
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            }
            else{
                res.render("secrets");
            }
        });
       
    });

   
});

app.post("/login",function(req,res){
    User.findOne({email:req.body.username},
           function(err,foundUser){
            if(err){
                console.log(err);
            }
            else{
                if(foundUser){
                      
                    
                    // if(foundUser.password===(req.body.password)){    
                    // }
                    bcrypt.compare(req.body.password, foundUser.password /*hash*/, function(err, result) {
                        if(result===true){
                            res.render("secrets");
                        }
                        else{
                            res.send("Incorrect Password,Please try again with right password!");
                        }
                    });
                   
                  
                    
                }
                else{
                    res.send("No such user exist,Please register!");
                }

            }
           
           });
});






app.listen(3000,function(req,res){
    console.log("Listening on port 3000");
})
