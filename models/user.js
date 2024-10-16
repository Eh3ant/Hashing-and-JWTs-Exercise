/** User class for message.ly */
const db = require("../db");
const ExpressError = require("../expressError");

const { BCRYPT_WORK_FACTOR } = require('../config');
const bcrypt = require('bcrypt');



/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    if (!username || !password || !first_name || !last_name || !phone) {
      throw new ExpressError("Missing required data", 400);
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
       RETURNING username,password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const user = result.rows[0];
    return user
  }


  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(`SELECT password FROM users WHERE username=$1`, [username]);

    const user = result.rows[0]

    if (user) {
      const isVali = await bcrypt.compare(password, user.password)
      return isVali;
    }

    return false
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users 
       SET last_login_at = current_timestamp
       WHERE username = $1
       RETURNING username`,
      [username]
    );
    const user = result.rows[0]
    if (!user) {
      throw new ExpressError("User not found", 404);
    }
  }


  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...]
   */

  static async all() {
    const result = await db.query(`SELECT username,first_name,last_name,phone FROM users ORDER BY last_name,first_name`)

    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(`SELECT username, first_name, last_name, phone, join_at, last_login_at
       FROM users 
       WHERE username = $1`, [username])

    const user = result.rows[0];

    if (!user) {
      throw new ExpressError(`No such user: ${username}`, 404)
    }
    return user
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
            m.body,
            m.sent_at,
            m.read_at,
            u.username AS to_username,
            u.first_name AS to_first_name,
            u.last_name AS to_last_name,
            u.phone AS to_phone
     FROM messages AS m
       JOIN users AS u ON m.to_username = u.username
     WHERE m.from_username = $1`,
      [username]
    );

    return result.rows.map(m => ({
      id: m.id,
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
      to_user: {
        username: m.to_username,
        first_name: m.to_first_name,
        last_name: m.to_last_name,
        phone: m.to_phone
      }
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id, m.from_username, m.body, m.sent_at, m.read_at,
              u.username AS from_username, u.first_name, u.last_name, u.phone
       FROM messages AS m
       JOIN users AS u ON m.from_username = u.username
       WHERE m.to_username = $1
       ORDER BY m.sent_at DESC`,
      [username]
    );

    return result.rows.map(row => ({
      id: row.id,
      from_user: {
        username: row.from_username,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at
    }));
  }
}


module.exports = User;