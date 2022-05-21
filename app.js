//jshint esversion:12

require('dotenv').config();  // fot creating and using env var
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');  // for encryption
const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds =7;  // Number of rounds for hashing via salting

const app = express();

app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");  // templating engine
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userAuthDB",{useNewUrlParser: true});


// ============== Secrets Schema =======================
const Secret_text_schema = mongoose.Schema({
    text : String
})
const secret_text = mongoose.model('SText',Secret_text_schema);
//=============== L1 - Basic Auth ====================== 

// const userSchema = mongoose.Schema({
//    email : String,
//    password : {
//        type : String ,
//        max : (10 , 'Maximum Password length is 10'),
//        min : (2 , 'Minimum Password length is 2')
//    },
//    secrets : [Secret_text_schema] 
// })

// ============= L2 - AES Encryption ===================

// const userSchema = new mongoose.Schema({
//     email : String ,
//     password : {
//                type : String ,
//                max : (10 , 'Maximum Password length is 10'),
//                min : (2 , 'Minimum Password length is 2')
//     },
//     secrets : [Secret_text_schema] 
// });

// userSchema.plugin(encrypt ,{secret : process.env.SECRET , encryptedFields :['password']});  // Add plugin before creating collection 

// ============= L3 - Hashing ==========================

// const userSchema = mongoose.Schema({
//        email : String,
//        password : {
//            type : String ,
//            max : (10 , 'Maximum Password length is 10'),
//            min : (2 , 'Minimum Password length is 2')
//        },
//        secrets : [Secret_text_schema] 
//     })

// ============ L4 - Salting with hashing ==============

const userSchema = mongoose.Schema({
    email : String,
    password : {
        type : String ,
        max : (10 , 'Maximum Password length is 10'),
        min : (2 , 'Minimum Password length is 2')
    },
    secrets : [Secret_text_schema] 
 })


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
app.get('/submit',(req,res)=>{
    res.render('submit');
});


app.post('/register',(req,res)=>{
    const Email = req.body.username;
    // const Password = md5(req.body.password);
    const Password = req.body.password;
    bcrypt.hash(Password,saltRounds,(error,hash)=>{
        if(!error){const newUser = new userAuth({
            email : Email ,
            password : hash
        })
        newUser.save((err)=>{
            if(!err){res.render('secrets'),{secrets :[]}}; 
        });}
    })
    // const newUser = new userAuth({
    //     email : Email ,
    //     password : saltPassword
    // })
    // newUser.save((err)=>{
    //     if(!err){res.render('secrets'),{secrets :[]}}; 
    // });
})

app.post('/login',(req,res)=>{
    const Email = req.body.username;
    // const Password = md5(req.body.password);
    const Password = req.body.password;

    userAuth.findOne({email : Email} , (err,result)=>{
        if(!err){
            // if(result.password === Password)
            // {res.render('secrets');}else{
            //     console.log('Password is Incorrect');
            //     console.log(Password);
            //     console.log(result.password)
            // }
            if(result)
            {bcrypt.compare(Password,result.password,function(err,BcryptRes){
                if(BcryptRes===true){
                    res.render('secrets');
                }
            })}else{
                console.log('Password is Incorrect');
            }
        }
        else{
            console.log(err);

        }
    })
})

app.post('/submit',(req,res)=>{
    const SText = req.body.secret;
    const newSecret = new secret_text({
        text : SText
    });
    newSecret.save();
    res.render('secrets',{secrets : []});
})


app.listen(process.env.POST||315,(error)=>{
    if(error){console.log(error);}else{
        console.log("Running at Port : 315");
    }
})