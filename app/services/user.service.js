const bcrypt = require("bcryptjs");

class UserService {
  constructor(client) {
    this.User = client.db().collection("users");
  }

  async findByUsername(username) {
    return await this.User.findOne({ username });
  }

  async create(payload) {
    const hashedPassword = await bcrypt.hash(payload.password, 10);
    const user = {
      username: payload.username,
      name: payload.name,
      password: hashedPassword,
    };
    const result = await this.User.insertOne(user);
    return { _id: result.insertedId, username: user.username, name: user.name };
  }

  async checkPassword(user, password) {
    return await bcrypt.compare(password, user.password);
  }
}

module.exports = UserService;
