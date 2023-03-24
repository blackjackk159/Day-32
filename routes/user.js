const bcrypt = require("bcrypt");
const validator = require("validator");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const router = require("express").Router();
const appError = require("../utils/appError");
const handleErrorAsync = require("../utils/handleErrorAsync");

// 產生 JWT token
const generateJWT = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE_IN,
  });
};

// isAuth middleware
const isAuth = handleErrorAsync(async (req, res, next) => {
  // 確認 token 是否存在
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return next(new appError(401, "你尚未登入！", next));
  }

  // 驗證 token 正確性
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);

  req.user = currentUser;
  next();
});

router.post(
  "/sign_up",
  handleErrorAsync(async (req, res, next) => {
    let { email, password, confirmPassword, name } = req.body;
    // 內容不可為空
    if (!email || !password || !confirmPassword || !name) {
      return next(new appError("欄位未填寫正確！", 400));
    }
    // 密碼正確
    if (password !== confirmPassword) {
      return next(new appError("密碼不一致！", 400));
    }
    // 密碼 8 碼以上
    if (!validator.isLength(password, { min: 8 })) {
      return next(new appError("密碼字數低於 8 碼", 400));
    }
    // 是否為 Email
    if (!validator.isEmail(email)) {
      return next(new appError("Email 格式不正確", 400));
    }

    // 加密密碼
    password = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      email,
      password,
      name,
    });

    // 產生 JWT
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE_IN,
    });

    // 將 token 回傳至 client
    res.status(200).json({
      status: "success",
      user: {
        token,
        name: newUser.name,
      },
    });
  })
);

router.post(
  "/sign_in",
  handleErrorAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new appError("帳號密碼不可為空", 400));
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return next(new appError("帳號或密碼錯誤，請重新輸入！", 400));
    }

    const auth = await bcrypt.compare(password, user.password);
    if (!auth) {
      return next(new appError("您的密碼不正確", 400));
    }

    const token = generateJWT(user._id);
    delete user.password;
    res.status(200).json({
      status: "success",
      user: {
        token,
        name: user.name,
      },
    });
  })
);

// routes/users
router.get(
  "/profile",
  isAuth,
  handleErrorAsync(async (req, res, next) => {
    req.user.password = undefined;
    res.status(200).json({
      status: "success",
      user: req.user,
    });
  })
);

router.post(
  "/updatePassword",
  isAuth,
  handleErrorAsync(async (req, res, next) => {
    let { password, confirmPassword, newPassword } = req.body;

    // 內容不可為空
    if (!password || !confirmPassword) {
      return next(new appError("欄位未填寫正確！", 400));
    }
    // 密碼正確
    if (password !== confirmPassword) {
      return next(new appError("密碼不一致！", 400));
    }
    // 密碼 8 碼以上
    if (!validator.isLength(newPassword, { min: 8 })) {
      return next(new appError("密碼字數低於 8 碼", 400));
    }

    // 比對密碼
    const user = await User.findById(req.user.id).select("+password");
    const auth = await bcrypt.compare(password, user.password);
    if (!auth) {
      return next(new appError("原密碼不正確", 400));
    }

    // 加密密碼
    password = await bcrypt.hash(newPassword, 12);

    // 更新密碼
    const newUser = await User.findByIdAndUpdate(req.user.id, {
      password,
    });

    // 產生 JWT
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE_IN,
    });

    // 將 token 回傳至 client
    res.status(200).json({
      status: "success",
      user: {
        token,
        name: newUser.name,
      },
    });
  })
);

module.exports = router;
