const mongoose = require("mongoose");
const MONGO_URI= "mongodb://localhost:27017/letsencrypt";

const connectDB = async ()=>{
    try{
        const connection = await mongoose.connect(MONGO_URI,{
            useUnifiedTopology:true
        })
        console.log(`letsencrypt db connected ${connection.connection.host}`);
    }catch(err){
        console.log(err);
        process.exit(1);
    }
}

module.exports = {
    connectDB
}