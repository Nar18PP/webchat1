import express from "express";
import http from "http";
import { Server } from "socket.io";
import mysql from "mysql2";
import dotenv from "dotenv"; // ใช้ dotenv แทน require
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import cors from "cors"; // หรือ require('cors');
import { verify } from "crypto";
cloudinary.config({
  cloud_name: "dcxgn1tr8",
  api_key: "775419989726717",
  api_secret: "VH5l_5ZBAVz9Y_rVrTpUUg_jtko",
});

// Set up multer for image file handling
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

function generateRandomSixDigit() {
  return Math.floor(100000 + Math.random() * 900000);
}

dotenv.config(); // โหลด environment variables

// Initialize Express
const app = express();
app.use(cors());
app.use(express.json());
// Create an HTTP server
const server = http.createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: "*", // หรือโดเมนที่คุณอนุญาตให้เชื่อมต่อ
    methods: ["GET", "POST"], // วิธีที่อนุญาตให้ใช้ (GET, POST, เป็นต้น)
  },
});
// Set up MySQL connection using environment variables
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Connect to MySQL database
db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to MySQL database");
});

// ตั้งค่าตัวส่งอีเมล
const transporter = nodemailer.createTransport({
  service: "gmail", // ใช้บริการของ Gmail หรือสามารถใช้บริการอื่นๆ
  auth: {
    user: process.env.EMAIL_USER, // ใส่อีเมลของคุณ
    pass: process.env.EMAIL_PASS, // ใส่รหัสผ่านของคุณ
  },
});
// ฟังก์ชันส่งอีเมล
const sendEmail = async (email, socket, res) => {
  const otp = generateRandomSixDigit();

  const mailOptions1 = {
    from: `Foraling <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `ຢືນຢັນ OTP ຂອງທ່ານ`,
    text: `ລະຫັດ OTP ຂອງທ່ານຄື: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions1);
    const addOtp = `INSERT INTO person (person_email, person_otp) values(?, '${otp}')`;
    db.query(addOtp, [email], (err, result) => {
      if (err) {
        console.log(err);
      } else {
        onCountEmail(email, socket);
      }
    });
  } catch (err) {
    res("sendMailError");
  }
};

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const file = req.file;

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload_stream(
      { resource_type: "auto", public_id: uuidv4() },
      (error, result) => {
        if (error) {
          return res.status(500).json({ message: "Upload failed", error });
        }
        res
          .status(200)
          .json({ message: "Upload successful", url: result.secure_url });
      }
    );

    result.end(file.buffer);
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Serve static files (optional, if you have an HTML frontend)
// app.use(express.static("public"));

let countEmail = [];
let intervalCountEmail = [];

const onCountEmail = async (email, socket) => {
  if (intervalCountEmail[email]) {
    return; // ถ้ามีการนับอยู่แล้วไม่ต้องเริ่มใหม่
  }
  try {
    countEmail[email] = 180; // กำหนดเวลาเริ่มต้น 15 วินาที

    intervalCountEmail[email] = setInterval(() => {
      countEmail[email] -= 1;
      socket.emit("countOtp", { countOtp: countEmail[email] });
      console.log(`Email: ${email}, Time left: ${countEmail[email]}`);

      if (countEmail[email] <= 0) {
        db.query(
          "DELETE FROM person where person_email = ? and person_number IS NULL",
          [email],
          (err, result) => {
            if (result) {
            }
          }
        );

        clearInterval(intervalCountEmail[email]);
        delete intervalCountEmail[email];
        delete countEmail[email];
      }
    }, 1000);
  } catch (error) {}
};

let usersInRoom = {};

// Handle Socket.IO connections
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);
  socket.on("sendOtp", (data, res) => {
    const checkEmail = `SELECT person_email FROM person WHERE person_email = ?`;
    db.query(checkEmail, [data.email], (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length > 0) {
          res({ status: "emailAlreadyExists" });
          console.log(55);
        } else {
          sendEmail(data.email, socket, res);
        }
      }
    });
  });

  socket.on("Register", async (data, res) => {
    try {
      const hashedPassword = await bcrypt.hash(data.password, 10);

      // ตรวจสอบว่าหมายเลขบุคคลซ้ำหรือไม่
      const [checkResult] = await db
        .promise()
        .query("SELECT person_number FROM person WHERE person_number = ?", [
          data.number,
        ]);

      if (checkResult.length > 0) {
        return res({ status: "numberAlreadyExists" });
      }
      const [checkOtp] = await db
        .promise()
        .query(
          "SELECT person_email, person_otp FROM person WHERE person_email = ? and person_otp = ?",
          [data.email, data.otp]
        );
      if (checkOtp.length < 1) {
        return res({ status: "otpIncorrect" });
      }

      // เพิ่มบุคคลใหม่ในฐานข้อมูล
      await db
        .promise()
        .query(
          "INSERT INTO person (person_number, person_password, person_email) values(?, ?, ?)",
          [data.number, hashedPassword, data.email]
        );

      // ดึง person_id
      const [personResult] = await db
        .promise()
        .query("SELECT person_id FROM person WHERE person_number = ?", [
          data.number,
        ]);

      if (personResult.length > 0) {
        const personId = personResult[0].person_id;
        db.query(
          "DELETE FROM person where person_email = ? and person_number IS NULL",
          [data.email],
          (err, result) => {
            if (result) {
            }
          }
        );
        clearInterval(intervalCountEmail[data.email]);
        delete intervalCountEmail[data.email];
        delete countEmail[data.email];

        return res({ status: "succ" });
      }
    } catch (err) {
      console.error(err);
      res({ status: "error", message: err.message });
    }
  });

  socket.on("logIn", async (data, res) => {
    try {
      const selectPassword =
        "SELECT person_id, person_password FROM person WHERE person_number = ?";
      db.query(selectPassword, [data.number], async (err, result) => {
        if (err) {
          console.error(err);
          return res({ status: "error", message: "Database error" });
        }

        if (result.length > 0) {
          const isPasswordValid = await bcrypt.compare(
            data.password,
            result[0].person_password
          );

          if (isPasswordValid) {
            const token = jwt.sign(
              { id: result[0].person_id },
              process.env.JWT_SECRET,
              { expiresIn: "1h" }
            );
            res({ status: "succ", token: token });
          } else {
            res({ status: "incorrect" });
          }
        } else {
          res({ status: "personNotFound" });
        }
      });
    } catch (error) {
      console.error(error);
      res({ status: "error", message: "Unexpected error occurred" });
    }
  });
  socket.on("checkToken", (data, res) => {
    const token = data.token;
    if (!token) return res({ status: "fail", massage: "tokenNotFound" });
    try {
      jwt.verify(token, process.env.JWT_SECRET);
      res({ status: "succ" });
    } catch (err) {
      res({ status: "fail" });
    }
  });
  // เมื่อ client ขอเวลาที่เหลือ
  socket.on("requestCountOtp", (data) => {
    if (countEmail[data.email]) {
      socket.emit("countOtp", { countOtp: countEmail[data.email] });
    } else {
      socket.emit("countOtp", { countOtp: 0 }); // ไม่มีการนับคืนค่า 0
    }
  });

  socket.on("reqListPerson", async (data, res) => {
    const { token, createGroup } = data;

    if (!token) {
      // return res({ status: "fail", message: "Token not found" });
    }

    try {
      // ตรวจสอบความถูกต้องของ token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // ดึงข้อมูลจากฐานข้อมูลตาม person_id จาก decoded
      const [listPerson] = await db
        .promise()
        .query(
          `SELECT * FROM chataliases chl INNER JOIN chats c ON chl.chat_id = c.chat_id WHERE person_id = ? ${
            createGroup ? "AND chat_type = 'private'" : ""
          }`,
          [decoded.id]
        );
      if (listPerson.length === 0) {
        return res({ status: "fail", message: "No contacts found" });
      }
      // ส่งข้อมูลกลับ
      return res({
        status: "succ",
        listPerson: listPerson,
        personId: decoded.id,
      });
    } catch (err) {
      console.error(err); // log ข้อผิดพลาดสำหรับ debugging
      // ถ้าเกิดข้อผิดพลาด เช่น token หมดอายุ หรือผิดพลาดอื่นๆ
      return res({ status: "fail", message: "Invalid or expired token" });
    }
  });
  socket.on("reqPersonId", async (data, res) => {
    const token = data.token;

    if (!token) {
      // return res({ status: "fail", message: "Token not found" });
    }
    try {
      // ตรวจสอบความถูกต้องของ token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      // ส่งข้อมูลกลับ
      return res({
        status: "succ",
        personId: decoded.id,
      });
    } catch (err) {
      console.error(err); // log ข้อผิดพลาดสำหรับ debugging
      // ถ้าเกิดข้อผิดพลาด เช่น token หมดอายุ หรือผิดพลาดอื่นๆ
      return res({ status: "fail", message: "Invalid or expired token" });
    }
  });

  socket.on("addPersonContact", async (data, res) => {
    const now = new Date();
    const formattedDate = `${now
      .toLocaleDateString("en-GB")
      .replace(/\//g, "/")} ${now.toLocaleTimeString("en-GB")}`;
    const [checkNumber] = await db
      .promise()
      .query("SELECT * FROM person WHERE person_number = ?", [data.number]);
    if (checkNumber.length > 0) {
      const [checkNameberContact] = await db.promise().query(
        `SELECT DISTINCT b.person_id AS other_person_id, p.person_number
FROM chataliases a
JOIN chataliases b
  ON a.chat_id = b.chat_id
JOIN person p
  ON b.person_id = p.person_id
WHERE a.person_id = ? AND b.person_id != ? AND person_number = ?;`,
        [data.personId, data.personId, data.number]
      );

      const [selPersonIdOther] = await db
        .promise()
        .query(
          "SELECT person_id, person_number FROM person WHERE person_number = ?",
          [data.number]
        );

      if (checkNameberContact.length > 0) {
        res({ status: "numberSaved" });
      } else {
        if (selPersonIdOther.length > 0) {
          const [selPersonNumber] = await db
            .promise()
            .query("SELECT person_number FROM person WHERE person_id = ?", [
              data.personId,
            ]);
          if (selPersonNumber.length > 0) {
            if (
              selPersonIdOther[0].person_number ===
              selPersonNumber[0].person_number
            ) {
              res({ status: "numberMe" });
              return;
            }

            const [insertChat] = await db
              .promise()
              .query("INSERT INTO chats (chat_datecreate) values(?)", [
                formattedDate,
              ]);
            if (insertChat) {
              const [selectChatId] = await db
                .promise()
                .query("SELECT chat_id FROM chats ORDER BY chat_id DESC");

              if (selectChatId[0]) {
                const [insertAlias] = await db
                  .promise()
                  .query(
                    `INSERT INTO chataliases (chat_id, person_id, other_person_id, calias_name) values(?, ?, ?, ?)`,
                    [
                      selectChatId[0].chat_id,
                      data.personId,
                      selPersonIdOther[0].person_id,
                      data.name,
                    ]
                  );
                if (insertAlias) {
                  const [insertAliasOther] = await db
                    .promise()
                    .query(
                      `INSERT INTO chataliases (chat_id, person_id, other_person_id, calias_name) values(?, ?, ?, ?)`,
                      [
                        selectChatId[0].chat_id,
                        selPersonIdOther[0].person_id,
                        data.personId,
                        selPersonNumber[0].person_number,
                      ]
                    );
                  if (insertAliasOther) {
                  }
                  res({ status: "succ" });
                } else {
                  console.log("insertAliasesFail");
                }
              }
            }
          }
        }
      }
    } else {
      res({ status: "numberNotFound" });
    }
  });
  socket.on("createGroup", async (data, res) => {
    const now = new Date();
    const formattedDate = `${now
      .toLocaleDateString("en-GB")
      .replace(/\//g, "/")} ${now.toLocaleTimeString("en-GB")}`;
    const { token, groupName, members, myId } = data;
    if (!token) {
      return;
    }
    const user = jwt.verify(token, process.env.JWT_SECRET);

    const [insertChat] = await db
      .promise()
      .query(
        "INSERT INTO chats (chat_datecreate, chat_name, chat_type) values(?, ?, ?)",
        [formattedDate, groupName, "public"]
      );
    if (insertChat) {
      const [selectChatId] = await db
        .promise()
        .query("SELECT chat_id FROM chats ORDER BY chat_id DESC");

      if (selectChatId[0]) {
        const [insertAlias] = await db
          .promise()
          .query(
            `INSERT INTO chataliases (chat_id, person_id, calias_name) values(?, ?, ?)`,
            [selectChatId[0].chat_id, members[0].person_id, ""]
          );
        if (insertAlias) {
          if (members) {
            members.map(async (e) => {
              const [insertAliasOther] = await db
                .promise()
                .query(
                  `INSERT INTO chataliases (chat_id, person_id, calias_name) values(?, ?, ?)`,
                  [selectChatId[0].chat_id, e.other_person_id, e.calias_name]
                );

              if (insertAliasOther) {
                res({ status: "succ" });
              }
            });
          }
        } else {
          console.log("insertAliasesFail");
        }
      }
    }
  });
  socket.on("sendMess", async (data) => {
    const now = new Date();
    const formattedDate = `${now
      .toLocaleDateString("en-GB")
      .replace(/\//g, "/")} ${now.toLocaleTimeString("en-GB")}`;
    const [insertMess] = await db
      .promise()
      .query(
        "INSERT INTO message (msg_text, chat_id, person_id, msg_datesend) values(?, ?, ?, ?)",
        [data.text, data.chatId, data.personId, formattedDate]
      );
    if (insertMess) {
      const [dataChat] = await db
        .promise()
        .query(
          "SELECT p.person_id, m.msg_id, ca.calias_name, m.msg_text AS msg_text, p.person_number AS sender, m.msg_datesend FROM message m JOIN person p ON m.person_id = p.person_id JOIN chataliases ca ON ca.person_id = p.person_id AND ca.chat_id = m.chat_id WHERE m.chat_id = ? ORDER BY m.msg_id ASC;",
          [data.chatId]
        );
      // ส่งข้อมูลแชทไปยังห้อง
      io.to(data.chatId).emit("chatPrivate", { dataChat: dataChat });
    }
  });

  socket.on("joinRoom", async (data) => {
    const { roomId, personId } = data;

    if (!roomId || !personId) {
      console.error("Invalid data received:", data);
      return;
    }

    // ตรวจสอบว่าห้องมีอยู่หรือไม่
    if (!usersInRoom[roomId]) {
      usersInRoom[roomId] = [];
    } else {
      console.log(`Room ${roomId} already exists.`);
    }

    // ตรวจสอบว่า personId นี้อยู่ในห้องแล้วหรือยัง
    if (!usersInRoom[roomId].includes(personId)) {
      usersInRoom[roomId].push(personId);
    }

    // ให้ socket เข้าร่วมห้อง
    socket.join(roomId);
    console.log(`${socket.id} joined room ${roomId}`);
    console.log(`Current users in room ${roomId}:`, usersInRoom[roomId]);

    const [dataChat] = await db
      .promise()
      .query(
        "SELECT p.person_id, m.msg_id, ca.calias_name, m.msg_text AS msg_text, p.person_number AS sender, m.msg_datesend FROM message m JOIN person p ON m.person_id = p.person_id JOIN chataliases ca ON ca.person_id = p.person_id AND ca.chat_id = m.chat_id WHERE m.chat_id = ? ORDER BY m.msg_id ASC;",
        [roomId]
      );

    // ส่งข้อมูลแชทไปยังห้อง
    io.to(roomId).emit("chatPrivate", { dataChat: dataChat });

    // // ถ้าผู้ใช้งานครบ 2 คน
    // if (usersInRoom[roomId].length === 2) {

    // }
  });

  // Handle disconnections
  socket.on("disconnect", () => {
    console.log("A user disconnected:", socket.id);
  });
});

// Define a simple route
app.get("/", (req, res) => {
  res.send("<h1>Hello, Socket.IO!</h1>");
});

// Start the server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
