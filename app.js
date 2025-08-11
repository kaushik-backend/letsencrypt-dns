// lets encrypt to be implemented for getting certificates automated renewals
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();
const userRoutes = require("./routes/userRoutes");
const customerDomainRoutes = require("./routes/customerDomainRoutes");
const { connectDB } = require('./utils/dbConnect');
const PORT = 8080;

connectDB();

app.use(express.json());

app.use("/api/users",userRoutes);
app.use("/api/customer-domain",customerDomainRoutes);
// app.use('/.well-known/acme-challenge', express.static(path.join(__dirname, 'certs', '.well-known/acme-challenge')));


// const https = require('https');
// const privateKey = fs.readFileSync(path.join(__dirname, 'certs', 'privkey.pem'), 'utf8');
// const certificate = fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'), 'utf8');
// const ca = fs.readFileSync(path.join(__dirname, 'certs', 'fullchain.pem'), 'utf8');

// const options = {
//   key: privateKey,
//   cert: certificate,
//   ca: ca,
// };

// https.createServer(options, app).listen(8080, () => {
//   console.log('Server running on https://localhost:8080');
// });

app.listen(PORT,()=>{
    console.log(`server is running on port ${PORT}`);
})
