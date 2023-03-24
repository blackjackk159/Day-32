//Init database
const DB = process.env.DB.replace("<DB_USER>", process.env.DB_USER)
  .replace("<DB_PASSWORD>", process.env.DB_PASSWORD)
  .replace("<DB_NAME>", process.env.DB_NAME);

const mongoose = require("mongoose");
mongoose.set("strictQuery", false);
mongoose.connect(DB, { useNewUrlParser: true }).then((con) => {
  console.log("DB connection successful!");
});