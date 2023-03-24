const appError = require("./appError")

// Custom Error
const customErrorHandler = () => new appError(`Your Error Message...`, 400);

// Handle dev error
const devErrorHandler = (err, req, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

// Handle prod error
const prodErrorHandler = (err, res) => {
  //Operational, trusted error: send message
  if (err.isOperational) {
    return res
      .status(err.statusCode)
      .json({ status: err.status, message: err.message });
  }

  // Programming or other unknown error: don't leak error details
  res.status(500).json({
    status: "error",
    message: "Unknown error happened...",
  });
};

// Global Error Handler
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  // 1) Error in development
  if (process.env.NODE_ENV === "dev") devErrorHandler(err, req, res);

  // 2) Error in production
  if (process.env.NODE_ENV === "prod") {
    let customError = { ...err };
    customError.message = err.message;

    if (customError.name === "CustomErrorChoice")
      customError = customErrorHandler(customError);
    prodErrorHandler(customError, res);
  }
};

module.exports = errorHandler;
