process.on("uncaughtException", (err) => {
  console.log("uncaughtException");
  console.log(err);
  process.exit(1);
});

const app = require("./config/appInit");
const server = app.listen(3000, () =>
  console.log(`server start at port ${3000}`)
);

process.on("unhandledRejection", (err) => {
  console.log("unhandledRejection");
  console.log(err);
  server.close(() => {
    console.log("server closed");
    process.exit(1);
  });
});
