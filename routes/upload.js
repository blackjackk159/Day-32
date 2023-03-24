const path = require("path");
const multer = require("multer");
const router = require("express").Router();

const upload = multer({
  limits: {
    fileSize: 2 * 1024 * 1024,
  },

  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== ".jpg" && ext !== ".png" && ext !== ".jpeg") {
      cb("檔案格式錯誤，僅限上傳 jpg、jpeg 與 png 格式。");
    }
    cb(null, true);
  },
}).any();

router.post("/", function (req, res) {
  upload(req, res, () => {
    // 這裡先回傳以下，接下來會串接 Imgur 將以成功處理的圖片上傳至 Imgur 相簿
    res.send({
      status: "success",
    });
  });
});

module.exports = router;
