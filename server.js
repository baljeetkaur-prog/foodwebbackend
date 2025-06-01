const express=require('express'); 
const app=express(); 
const port=9000; 
require('dotenv').config()
app.use(express.json()); 
const mongoose=require('mongoose'); 
var cors=require('cors')
app.use(cors());
const nodemailer = require('nodemailer');

const uploadpath = "public/uploads";
const fs = require("fs");

const multer = require('multer')

const mystorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadpath)
  },
  filename: function (req, file, cb) {
    const prefix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, prefix + file.originalname)
  }
})

const upload = multer({ storage: mystorage })
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,
  secure: true,
  auth: {
    user: `${process.env.SMTP_UNAME}`,
    pass: `${process.env.SMTP_PASS}`
  },
  tls: {
    rejectUnauthorized: false
  }
})

app.use(cors())
const bcrypt=require('bcrypt'); 
const saltRounds=10; 
mongoose.connect('mongodb+srv://baljeetkor6:NhoYMNLXxKYBVJFY@cluster0.geq4lik.mongodb.net/foodweb?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('MongoDB Connected')).catch((e) => console.log("Unable to connect to MongoDB" + e.message));
const accSchema=new mongoose.Schema({username:String, email: {type:String, unique:true}, password:String, usertype:String}, {versionKey:false})
const accModel=mongoose.model("account", accSchema, "account"); 
app.post("/api/signup", async (req, res) => {
  try {
    const { uname, email, password } = req.body;

    const existinguser = await accModel.findOne({ email });
    if (existinguser) {
      return res.status(409).send({ success: false, message: "Email already registered" });
    }

    const hashedpassword = await bcrypt.hash(password, saltRounds);
    let usertype = "user";

    if (email.endsWith("@admin.com")) {
      usertype = "admin";
    }

    const newrecord = new accModel({
      username: uname,
      email,
      password: hashedpassword,
      usertype,
    });

    const result = await newrecord.save();
    if (result) {
      return res.status(200).send({ success: true, message: "Signup Successful" });
    } else {
      return res.status(500).send({ success: false, message: "Signup Failed" });
    }
  } catch (e) {
    console.log("Signup error", e);
    return res.status(500).send({ success: false, message: "An unexpected error occurred. Please try again later." });
  }
});
app.post("/api/login", async(req,res)=>
{
    try
    {
        const {luname,lpass}=req.body; 
        const result=await accModel.findOne({username:luname}); 
        if(!result)
        {
            res.status(404).send({success:false, message:"User Not Found"})
        }
        const ismatch=bcrypt.compareSync(lpass, result.password); 
        if(!ismatch)
        {
            res.status(401).send({success:false, message:"Invalid Credentials"})
        }
        else
        {
          res.send({ success: true, udata: result });
    }
  }
    catch(e)
    {
        res.status(500).send("An unexpected error occurred. Please try again later.")
        console.log(e.message)
    }
})
app.post("/api/logout", (req, res) => {
  res.json({ success: true, message: "Logged out successfully" })
})
app.get("/api/fetchallusers",async(req,res)=>
{
    try
    {
        const users=await accModel.find({},'username email'); 
        if(users.length>0)
        {
            res.status(200).send({success:true, users:users})
        }
        else
        {
            res.status(400).send({success:false, message:"No User Found"})
        }
    }
    catch(e)
    {
        res.status(500).send({success:false, message: "Error while fetching users"})
        console.log(e)
    }
})
app.delete("/api/deluser/:id",async(req,res)=>
{
    try
    {
        const result=await accModel.findByIdAndDelete(req.params.id); 
        if(result)
        {
            res.status(200).send({success:true, message:"User deleted successfully"})
        }
        else
        {
            res.status(404).send({success:false, message:"User not found"})
        }
    }
    catch(e)
    {
        res.status(500).send({success:false, message: "Server error: "+e.message})
    }
})
app.get("/api/searchuser",async(req,res)=>{
    try
    {
        const {email}=req.query; 
        const result=await accModel.findOne({email:email}); 
        if(!result)
        {
            res.status(404).send({success:false, message:"User not found"})
        }
        else
        {
            res.status(200).send({success:true, username:result.username, email:result.email})
        }

    }
    catch(e)
    {
        res.status(500).send({success:false, message:"Server error"})
        console.log(e.message)
    }
})
app.post("/api/createadmin",async(req,res)=>
{
    try
    {
        const {uname, email, password, usertype}=req.body; 
        const existinguser=await accModel.findOne({email}); 
        if(existinguser)
        {
            return res.status(404).send({success:false, message:"Email already registered"})
        }
        const hashedpassword=await bcrypt.hash(password,saltRounds); 
        const newrecord=accModel({username:uname, email:email, password:hashedpassword, usertype}); 
        const result=await newrecord.save(); 
        if(result)
        {
            res.status(200).send({success:true, message:"Admin Created Successfully"})
        }
        else
        {
            res.status(500).send({success:false, message:"Signup Failed"})
        }
    }
    catch(e)
    {
        res.status(500).send("Error Occured "+e.message)
    }
})
const prodSchema=new mongoose.Schema({name:String, description:String, price:Number,originalprice:Number,  image: String, instock:Boolean, addedon: Date}, {versionKey:false}); 
const prodModel=mongoose.model("product", prodSchema, "product"); 
app.post("/api/manageprod", upload.single('image'), async (req, res) => {
    try {
      var imagename = "noimage.jpg";
      if (req.file) {
        imagename = req.file.filename
      }
      const {name, description, price, originalprice, instock}=req.body; 
      const newrecord = new prodModel({ name, description, price, originalprice, image:imagename, instock:instock==='true' || instock===true, addedon: new Date() })
      const result = await newrecord.save();
      if (result) {
        res.status(200).send({success:true, message:"Product added successfully"})
      }
      else {
        res.status(200).send({success:false, message:"Product is not added"})
      }
    }
    catch (e) {
      res.status(500).send("Error occured " + e.message)
      console.log(e.message)
    }
  
  })
app.get("/api/fetchproducts",async(req,res)=>
{
    try
    {
        const result=await prodModel.find(); 
        if(result.length>0)
        {
            res.status(200).send({success:true, result}); 
        }
        else
        {
            res.status(200).send({success:false, message:"No Products Found"})
        }
    }
    catch(e)
    {
        res.status(500).send({success:false, message:"Server Message"})
    }
})
app.get("/api/getproddetailsbyid", async (req, res) => {
  try {
    const result = await prodModel.findById(req.query.prodid);
    if (result) {
      res.send({ success: true, pdata: result });
    } else {
      res.send({ success: false, message: "Product not found" });
    }
  } catch (e) {
    res.status(500).send("Error Occurred: " + e.message);
  }
});
app.put("/api/updateprod",upload.single('image'),async(req,res)=>{
    const {pname, descrip,price, productid, originalprice, existingimage}=req.body; 
    const instock=req.body.instock==='true' || req.body.instock===true; 
    const updatedimg=req.file?req.file.filename:existingimage; 
    try
    {
        const result=await prodModel.findByIdAndUpdate(productid, {name:pname, description:descrip, price:price, originalprice: originalprice, image:updatedimg, instock:instock},{new:true}); 
        if(!result)
        {
            return res.status(404).send({success:false, message:"Product not found"})

        }
        res.status(200).send({success:true, message:"Product updated successfully", result:result}); 
    }
    catch(e)
    {
        res.status(500).send({success:false, message:"Error updating product", error:e.message}); 
        console.log(e); 
    }
})
app.delete("/api/deleteprod/:_id",async(req,res)=>{
    try
    {
        const delprod=await prodModel.findById(req.params._id); 
        if(!delprod)
        {
            return res.status(404).send({success:false, message:"Product not found"})
        }
        const imagename=delprod.image; 
        const result=await prodModel.findByIdAndDelete(req.params._id)
        if(result)
        {
            if(imagename!=="noimage.jpg"){
                const imagepath=`${uploadpath}/${imagename}`; 
                if(fs.existsSync(imagepath)){
                    fs.unlinkSync(imagepath)
                }
            }
            res.status(200).send({success:true,message:"Product deleted successfully"})
        }
        else
        {
            res.status(500).send({success:false, message:"Product not deleted"})
        }
    }
    catch(e)
    {
        res.status(500).send({success:false, message:"Server Error Occured", error:e.message}); 
    }
})
const cartSchema = new mongoose.Schema({ prodid: { type: mongoose.Schema.Types.ObjectId, ref: 'product' }, image: String, prodname: String, quantity: Number, email: String, price:Number, originalprice:Number , instock:Boolean, totalprice:Number  }, { versionKey: false });
const cartModel = mongoose.model("cart", cartSchema, "cart");
app.post("/api/savecart", async (req, res) => {
  try {
    const newrecord = new cartModel({ prodid: req.body.prodid, image: req.body.imgname, prodname: req.body.pname, quantity: req.body.quantity, email: req.body.email,price:req.body.price, originalprice: req.body.originalprice, instock:req.body.instock, totalprice: req.body.totalprice})
    const result = await newrecord.save();
    if (result) {
      res.status(200).send({ success: true });
    }
    else {
      res.status(500).send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.get("/api/fetchcart/:email", async (req, res) => {
  try {
    const result = await cartModel.find({ email: req.params.email });
    if (result.length > 0) {
      res.send({ success: true, cartdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
app.delete("/api/delcart/:_id", async (req, res) => {
  try {
    const result = await cartModel.findByIdAndDelete(req.params._id)
    if (result) {
      res.status(200).send({ success: true })
    }
    else {
      res.status(500).send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send(e.message)
  }
})
const orderSchema=new mongoose.Schema({email:String, address:{house:String, street:String, city:String, state:String, pincode:String}, pmethod:{type:String,enum:['cod','card']}, carddetails:{cardnum:String, expiry:String, cvv:String, cardname:String}, saveaddress:[Object], products:[{prodid:String, prodname:String, quantity: Number, price: Number, total:Number, image:String}], totalamount:Number, orderDate: Date, status:String}, {versionKey:false})
const orderModel=mongoose.model("order",orderSchema,"order"); 
app.post("/api/saveorder", async (req, res) => {
  try {
    const { email, address, saveaddress, paymentmethod, carddetails } = req.body;

    if (!email || !address || !paymentmethod) {
      return res.status(400).send({ success: false, message: "Missing required fields" });
    }

    const cartitems = await cartModel.find({ email });

    if (!cartitems || cartitems.length === 0) {
      return res.status(400).send({ success: false, message: "Cart is empty" });
    }

    const products = cartitems.map(item => ({
      prodid: item.prodid,
      prodname: item.prodname,
      quantity: item.quantity,
      price: item.price,
      total: item.price * item.quantity,
      image: item.image
    }));

    const totalamount = products.reduce((sum, item) => sum + item.total, 0);

    // Correct IST Date Conversion
    const currentDateUTC = new Date();
    const ISTOffset = 5.5 * 60 * 60 * 1000; // IST offset in milliseconds
    const currentDateIST = new Date(currentDateUTC.getTime() + ISTOffset);

    const order = new orderModel({
      email,
      address,
      saveaddress,
      pmethod:paymentmethod,
      carddetails: paymentmethod === 'card' ? carddetails : {},
      products,
      totalamount,
      orderDate: currentDateIST, 
      status: "Payment received, order processing"
    });

    await order.save();
    await cartModel.deleteMany({ email });

    console.log("Order saved. Cart cleared. Email:", email);
    res.status(200).json({ success: true, message: 'Order placed successfully' });

  } catch (error) {
    console.error("Order Save Error:", error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.get('/api/getaddress/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await orderModel.find({ email, saveaddress: true }).sort({ orderDate: -1 });

        if (result.length>0) {
            const addresses = result.map(item => item.address);
            res.send({ success: true, addresses });
        } else {
            res.send({ success: false, message: "No saved address found" });
        }
    } catch (e) {
        console.error(e);
        res.status(500).send({ success: false, message: "Server error" });
    }
});
app.get("/api/fetchorderinfo", async (req, res) => {
  try {
    const result = await orderModel.findOne({ email: req.query.email }).sort({ "orderDate": -1 });
    console.log(result);
    if (result) {
      res.send({ success: true, orderdata: result })
    }
    else {
      res.send({ success: false })
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
    console.log(e.message)
  }
})
app.get("/api/fetchorders", async (req, res) => {
  try {
    const inputDate = req.query.odate; //Eg: 2025-04-29
    //converting inputData to the start and end of the day
    const startDay = new Date(`${inputDate}T00:00:00.000Z`);
    const endDay = new Date(`${inputDate}T23:59:59.999Z`)
    //query for date within the date range
    const result = await orderModel.find({ orderDate: { $gte: startDay, $lte: endDay } }).sort({ orderDate: -1 });
    if (result.length > 0) {
      res.send({ success: true, orddata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.status(500).send("Error Occured " + e.message)
  }
});

app.post("/api/updatestatus", async (req, res) => {
  try {
    const { orderId, nstatus } = req.body;

    if (!orderId || !nstatus) {
      return res.status(400).json({ success: false, message: "Missing orderId or newStatus" });
    }

    const updatedOrder = await orderModel.findByIdAndUpdate(
      orderId,
      { status: nstatus },
      { new: true }
    );

    if (!updatedOrder) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }

    res.json({ success: true, message: "Status updated", order: updatedOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.get("/api/fetchusersorders", async (req, res) => {
  try {
    const result = await orderModel.find({ email: req.query.email }).sort({ orderDate: -1 });
    if (result.length > 0) {
      res.send({ success: true, orddata: result });
    }
    else {
      res.send({ success: false });
    }
  }
  catch (e) {
    res.send({ success: false, errormessage: e.message })
  }
});
app.get("/api/getprodsbyname/:text",async(req,res)=>{
  try
  {
    var searchtext=req.params.text; 
    const result=await prodModel.find({name: { $regex: '.*' + searchtext, $options: 'i'}})
    if(result.length>0)
    {
      res.send({success:true, pdata:result}); 
    }
    else
    {
      res.send({success:false}); 
    }
  }
  catch(e)
  {
    res.send({success:false, errmessage:e.message}); 
  }
})
const CSECRET_KEY="6LeWZkYrAAAAAIR2IkvOM5kRSOnIgKtcRpb0Coea"
app.post("/api/contactus", async (req, res) => {
  const {name,email,message,captchatoken}=req.body; 
  if(!captchatoken)
  {
    return res.status(400).send({success:false, message:"Captcha token is missing"})
  }
  try {
    const response=await fetch("https://www.google.com/recaptcha/api/siteverify",
      {
        method:"POST", 
        headers:{"Content-Type":"application/x-www-form-urlencoded"}, 
        body: new URLSearchParams({
          secret: CSECRET_KEY, 
          response:captchatoken, 
        })
      }
    ); 
    const responsedata=await response.json(); 
    console.log("Google reCAPTCHA response: ",responsedata); 
    if(!responsedata.success)
    {
      return res.status(400).send({success:false, message:"reCAPTCHA verification failed", details:responsedata}); 
    }
    const mailoptions =
    {
      from: 'class@gtbinstitute.com',
      to: 'gtbtrial@gmail.com',
      replyTo: req.body.email,
      subject: 'Message from website- contact us',
      html: `<b>Name: <b> ${req.body.name}<br/><b>Email: </b> ${req.body.email}
      <br/><b>Message: </b> ${req.body.message}`
    };
    transporter.sendMail(mailoptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).send('Error sending email')
      }
      else {
        console.log('Email send: ' + info.response);
        res.status(200).send({success:true,message:"Message sent successfully"})
      }
    });
  }
  catch (e) {
    res.status(500).send({ code: -1, errmsg: e.message });
  }
})
app.put("/api/changepassword", async(req,res)=>
{
  try
  {
    const {uid,cpass,npass}=req.body; 
    const result=await accModel.findOne({_id:uid}); 
    if(!result)
    {
      res.send({success:false, message:"Invalid ID"})
    }
    const isMatch=bcrypt.compareSync(cpass,result.password); 
    if(!isMatch)
    {
      return res.send({success:false, message:"Incorrect Current Password"}); 
    }
    const hash=bcrypt.hashSync(npass,saltRounds); 
    const updateresult=await accModel.updateOne({_id:uid}, {password:hash}); 
    if(updateresult){
      res.status(200).send({success:true, message:"Password Changed Successfully"})
    }
    else
    {
      res.status(500).send({success:false, message:"Error while changing password"})
    }
  }
  catch(e)
  {
    res.status(500).send({success:false, message:e.message}); 
  }

})
app.listen(port, () => {
    console.log(`Server running on port ${port}`)
  })