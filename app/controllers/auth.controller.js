const jwt = require("jsonwebtoken");
const UserService = require("../services/user.service");
const MongoDB = require("../utils/mongodb.util");
const ApiError = require("../api-error");
const config = require("../config");

exports.register = async (req, res, next) => {
  if (!req.body?.username || !req.body?.password) {
    return next(
      new ApiError(400, "Tên đăng nhập và mật khẩu không được để trống"),
    );
  }

  try {
    const userService = new UserService(MongoDB.client);
    const existed = await userService.findByUsername(req.body.username);
    if (existed) {
      return next(new ApiError(400, "Tên đăng nhập đã tồn tại"));
    }
    const user = await userService.create(req.body);
    return res.send({ message: "Đăng ký thành công", user });
  } catch (error) {
    return next(new ApiError(500, "Có lỗi xảy ra khi đăng ký tài khoản"));
  }
};

exports.login = async (req, res, next) => {
  if (!req.body?.username || !req.body?.password) {
    return next(
      new ApiError(400, "Tên đăng nhập và mật khẩu không được để trống"),
    );
  }

  try {
    const userService = new UserService(MongoDB.client);
    const user = await userService.findByUsername(req.body.username);
    if (!user || !(await userService.checkPassword(user, req.body.password))) {
      return next(new ApiError(401, "Sai tên đăng nhập hoặc mật khẩu"));
    }
    const token = jwt.sign(
      { id: user._id, username: user.username },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn },
    );
    return res.send({
      token,
      user: { _id: user._id, username: user.username, name: user.name },
    });
  } catch (error) {
    return next(new ApiError(500, "Có lỗi xảy ra khi đăng nhập"));
  }
};
