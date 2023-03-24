require("dotenv").config();
require("./dbInit");
const express = require("express");
const app = express();
const userRoutes = require("../routes/user");
const uploadRouter = require('../routes/upload');
const errorHandler = require("../utils/errorHandler");

// Body parser
app.use(express.json()); //to JSON
app.use(express.urlencoded({ extended: true })); //recognize strings or arrays

app.use("/users", userRoutes);
app.use('/api/v1/upload', uploadRouter);

// error handler
// 錯誤處理的 middleware 相較一般 middleware 會多一個 err 引數
app.use(errorHandler);

module.exports = app;
