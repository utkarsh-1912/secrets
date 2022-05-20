//jshint esversion:12

const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption');

const app = express();

app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");  // templating engine
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userAuthDB",{useNewUrlParser: true});


//=============== L1 - Basic Auth ====================== 

// const userSchema = mongoose.Schema({
//    email : String,
//    password : {
//        type : String ,
//        max : (10 , 'Maximum Password length is 10'),
//        min : (2 , 'Minimum Password length is 2')
//    }
// })

// ============= L2 - AES Encryption ===================

const userSchema = new mongoose.Schema({
    email : String ,
    password : {
               type : String ,
               max : (10 , 'Maximum Password length is 10'),
               min : (2 , 'Minimum Password length is 2')
           }
});

const secret ="UtkristiEncryptionSecret";
userSchema.plugin(encrypt ,{secret : secret , encryptedFields :['password']});  // Add plugin before creating collection 

const userAuth = mongoose.model("userAuth",userSchema);

app.get('/',(req,res)=>{
    res.render('home');
})

app.get('/login',(req,res)=>{
    res.render('login');
})

app.get('/register',(req,res)=>{
    res.render('register');
})
app.get('/logout',(req,res)=>{
    res.redirect('/');
})

app.post('/register',(req,res)=>{
    const Email = req.body.username;
    const Password = req.body.password;
    
    const newUser = new userAuth({
        email : Email ,
        password : Password
    })
    newUser.save((err)=>{
        if(!err){res.render('secrets')}; 
    });
})

app.post('/login',(req,res)=>{
    const Email = req.body.username;
    const Password = req.body.password;

    userAuth.findOne({email : Email} , (err,result)=>{
        if(!err){
            if(result.password === Password)
            {res.render('secrets');}else{
                console.log('Password is Incorrect');
            }
        }
        else{
            console.log(err);

        }
    })
})

app.listen(process.env.POST||315,(error)=>{
    if(error){console.log(error);}else{
        console.log("Running at Port : 315");
    }
})