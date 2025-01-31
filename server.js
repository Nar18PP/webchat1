import express, { response } from "express";
import cors from "cors";
import { Server } from "socket.io";
import http from "http";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { sequelize, connectDB } from "./models/database.js";
import bcrypt from "bcryptjs";
import multer from "multer";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";
import sharp from "sharp";
dotenv.config(); // โหลดไฟล์ .env

const now = new Date();
const formattedDate = `${now
  .toLocaleDateString("en-GB")
  .replace(/\//g, "/")} ${now.toLocaleTimeString("en-GB")}`;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  cors({
    origin: "*", // ใส่ URL ของ frontend ที่อนุญาต
  })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ให้บริการไฟล์ในโฟลเดอร์ uploads
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/img", express.static(path.join(__dirname, "img")));

const server = http.createServer(app);
// Socket.IO CORS การตั้งค่าเฉพาะ
const io = new Server(server, {
  cors: {
    origin: "*", // Frontend origin
  },
});

const PORT = process.env.PORT || 3002;

// เชื่อมต่อฐานข้อมูล
connectDB();

// ตั้งค่าตัวส่งอีเมล
const transporter = nodemailer.createTransport({
  service: "gmail", // ใช้บริการของ Gmail หรือสามารถใช้บริการอื่นๆ
  auth: {
    user: process.env.EMAIL_USER, // ใส่อีเมลของคุณ
    pass: process.env.EMAIL_PASS, // ใส่รหัสผ่านของคุณ
  },
});
// ฟังก์ชันส่งอีเมล
const sendEmail = async (email, socket, response) => {
  const otp = Math.floor(Math.random() * (999999 - 100000 + 1)) + 100000;

  const mailOptions1 = {
    from: `Foraling <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `ຢືນຢັນ OTP ຂອງທ່ານ`,
    text: `ລະຫັດ OTP ຂອງທ່ານຄື: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions1);

    const [result1] = await sequelize.query(
      "INSERT INTO person (person_email, person_otp) values(?, ?)",
      {
        replacements: [email, otp],
      }
    );
    if (result1) {
      onCountEmail(email, socket);
      response("sendMailSuccess");
    }
  } catch (err) {
    response("sendMailError");
  }
};

const validateEmail = (email) => {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
};

const UPLOAD_FOLDER = path.join(__dirname, "uploads");
// สร้างโฟลเดอร์ถ้ายังไม่มี
if (!fs.existsSync(UPLOAD_FOLDER)) {
  fs.mkdirSync(UPLOAD_FOLDER);
}

// ตั้งค่าการเก็บไฟล์ที่อัปโหลด
const storage = multer.memoryStorage(); // เก็บไฟล์ในหน่วยความจำ

const upload = multer({ storage: storage });

// สร้าง route สำหรับการรับไฟล์
app.post("/upload", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send("ไม่มีไฟล์ที่อัปโหลด");
    }

    const outputFileName = Date.now() + ".webp";
    const outputFilePath = path.join(__dirname, "uploads", outputFileName);

    // const [result] = await sequelize.query(
    //   "SELECT store_image FROM store WHERE person_id = ?",
    //   {
    //     replacements: [req.body.userId],
    //   }
    // );

    const [result] = await sequelize.query(
      "SELECT person_id FROM store WHERE person_id = ?",
      {
        replacements: [req.body.userId],
      }
    );
    if (result.length > 0) {
      const [result] = await sequelize.query(
        "SELECT store_image FROM store WHERE person_id = ?",
        {
          replacements: [req.body.userId],
        }
      );
      if (result.length > 0) {
        const [result1] = await sequelize.query(
          "UPDATE store SET store_image = ? WHERE person_id = ?",
          {
            replacements: [outputFileName, req.body.userId],
          }
        );
        const OldNameImg = result[0].store_image;
        const filePath = path.join(__dirname, "uploads", OldNameImg);
        console.log(OldNameImg);
        if (fs.existsSync(filePath)) {
          fs.unlink(filePath, (err) => {
            if (err) {
              console.error("เกิดข้อผิดพลาดในการลบไฟล์:", err);
            } else {
              console.log("ลบไฟล์สำเร็จ:", filePath);
            }
          });
        }
      }
    } else {
      const [result] = await sequelize.query(
        "INSERT INTO imagetest (image, person_id) value(?, ?)",
        {
          replacements: [outputFileName, req.body.userId],
        }
      );
    }
    await sharp(req.file.buffer).webp().toFile(outputFilePath);

    res.status(200).send({
      message: "อัปโหลดและแปลงไฟล์สำเร็จ",
      file: outputFileName,
      nameImgTest: `${outputFileName}`,
    });
  } catch (error) {}
});

// Endpoint สำหรับการตรวจสอบ token
app.post("/verify-token", (req, res) => {
  const { token } = req.body; // ดึง token จาก body ของ request
  if (!token) {
    return res
      .status(401)
      .json({ status: "invalid", message: "No token provided" });
  }

  // ใช้ jwt.verify() เพื่อตรวจสอบ token
  jwt.verify(token, "secretkey", async (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json({ status: "invalid", message: "Invalid or expired token" });
    }

    // ถ้า token valid, ส่งข้อมูลที่ decode มาให้ client
    const [result] = await sequelize.query(
      "SELECT person_id FROM person WHERE (person_email = ? OR person_username = ?)",
      {
        replacements: [decoded.username, decoded.username],
      }
    );
    res.json({
      status: "valid",
      decoded,
      userId: result[0].person_id,
    });
  });
});

let countEmail = [];
let intervalCountEmail = [];

const onCountEmail = async (email, socket) => {
  if (intervalCountEmail[email]) {
    return; // ถ้ามีการนับอยู่แล้วไม่ต้องเริ่มใหม่
  }
  try {
    countEmail[email] = 30; // กำหนดเวลาเริ่มต้น 15 วินาที

    intervalCountEmail[email] = setInterval(() => {
      countEmail[email] -= 1;
      socket.emit("countOtp", { countOtp: countEmail[email] });
      console.log(`Email: ${email}, Time left: ${countEmail[email]}`);

      if (countEmail[email] <= 0) {
        sequelize.query(
          "DELETE FROM person where person_email = ? and person_fname IS NULL",
          {
            replacements: [email],
          }
        );
        clearInterval(intervalCountEmail[email]);
        delete intervalCountEmail[email];
        delete countEmail[email];
      }
    }, 1000);
  } catch (error) {}
};

// const sqlSelStoretAllAndLike = `SELECT
//            s.*, CASE
//              WHEN l.person_id IS NOT NULL THEN true
//              ELSE false
//            END AS is_liked
//          FROM store s
//          LEFT JOIN likedshops l
//            ON s.store_id = l.store_id AND l.person_id = ?;`;
const sqlSelStoretAllAndLike = `SELECT 
    s.*,
    IFNULL(COUNT(l.person_id), 0) AS like_count,
    CASE 
        WHEN EXISTS (
            SELECT 1 
            FROM likedshops l2 
            WHERE l2.store_id = s.store_id AND l2.person_id = ?
        ) THEN true
        ELSE false
    END AS is_liked
FROM store s
LEFT JOIN likedshops l
    ON s.store_id = l.store_id
GROUP BY s.store_id, s.store_name
ORDER BY like_count DESC;
`;
const sqlSelStoreAllLike = `SELECT 
  s.*,
  true AS is_liked,
  (SELECT COUNT(*) 
   FROM likedshops l2 
   WHERE l2.store_id = s.store_id) AS like_count
FROM store s
INNER JOIN likedshops l
  ON s.store_id = l.store_id
WHERE l.person_id = ?
ORDER BY l.likeshops_id DESC;`;
const sqlSelStoretAll = `SELECT 
    s.*,
    IFNULL(COUNT(l.person_id), 0) AS like_count,
    CASE 
        WHEN EXISTS (
            SELECT 1 
            FROM likedshops l2 
            WHERE l2.store_id = s.store_id
        ) THEN false
    END AS is_liked
FROM store s
LEFT JOIN likedshops l
    ON s.store_id = l.store_id
GROUP BY s.store_id, s.store_name;`;

const sqlSelMystore = `SELECT 
  s.*, 
  CASE 
    WHEN EXISTS (
      SELECT 1 
      FROM likedshops l 
      WHERE l.store_id = s.store_id AND l.person_id = ?
    ) THEN true 
    ELSE false 
  END AS is_liked,
  IFNULL(COUNT(l.store_id), 0) AS like_count
FROM store s 
LEFT JOIN likedshops l
  ON s.store_id = l.store_id
WHERE s.store_id = ?
GROUP BY s.store_id, s.store_name;
`;
const sqlSelComments = `SELECT * FROM comments where store_id = ? ORDER BY comment_id DESC;`;

io.on("connection", (socket) => {
  socket.on("reqDataStoreAll", async (userId) => {
    if (userId) {
      const [resultStoreAllAndLike] = await sequelize.query(
        sqlSelStoretAllAndLike,
        {
          replacements: [userId],
        }
      );
      const [resultStoreAllLike] = await sequelize.query(sqlSelStoreAllLike, {
        replacements: [userId],
      });

      if (resultStoreAllAndLike && resultStoreAllLike) {
        // ส่งข้อมูลร้านพร้อมสถานะการกดใจ
        socket.emit("resDataStoreAll", {
          resDataStoreAll: resultStoreAllAndLike,
          resDataStoreAllLike: resultStoreAllLike,
        });
      }
    } else {
      const [result] = await sequelize.query(sqlSelStoretAll);
      if (result) {
        // ส่งข้อมูลร้านทั้งหมด
        socket.emit("resDataStoreAll", { resDataStoreAll: result });
      }
    }
  });

  socket.on("checkUsernameRegister", async (inputUsername, response) => {
    try {
      const [result] = await sequelize.query(
        "SELECT person_username FROM person WHERE person_username = ?",
        {
          replacements: [inputUsername],
        }
      );

      if (result.length > 0) {
        response("failed");
      } else {
        response("success");
      }
    } catch (error) {}
  });
  socket.on("checkEmail", async (email, response) => {
    if (validateEmail(email)) {
      const [result] = await sequelize.query(
        "SELECT person_email FROM person WHERE person_email = ?",
        {
          replacements: [email],
        }
      );
      if (result.length > 0) {
        response("have an email");
      } else {
        sendEmail(email, socket, response);
      }
    } else {
      response("failed");
    }
  });
  // เมื่อ client ขอเวลาที่เหลือ
  socket.on("requestCountOtp", (email) => {
    if (countEmail[email]) {
      socket.emit("countOtp", { countOtp: countEmail[email] });
    } else {
      socket.emit("countOtp", { countOtp: 0 }); // ไม่มีการนับคืนค่า 0
    }
  });
  //checkEmailandOtp
  socket.on("checkEmailandOtp", async (email, otp, response) => {
    const [result] = await sequelize.query(
      "SELECT person_email, person_otp FROM person where person_email = ? and person_otp = ?",
      {
        replacements: [email, otp],
      }
    );
    if (result.length > 0) {
      response("checkSuccess");
    } else {
      response("checkFailed");
    }
  });
  //checkPassword
  socket.on(
    "insertPersonRegis",
    async (fname, lname, username, gender, email, password, response) => {
      const [result] = await sequelize.query(
        "SELECT person_email FROM person where person_email = ? and person_fname IS NOT NULL",
        {
          replacements: [email],
        }
      );
      if (result.length > 0) {
        response("have an email");
      } else {
        const [result] = await sequelize.query(
          "SELECT person_username FROM person where person_username = ? and person_fname IS NOT NULL",
          {
            replacements: [username],
          }
        );
        if (result.length > 0) {
          response("have a username");
        } else {
          if ((fname, lname, username, gender, email, password)) {
            const saltRounds = 12;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const [result] = await sequelize.query(
              "INSERT INTO person (person_fname, person_lname, person_username, person_gender, person_email, person_password) values(?, ?, ?, ?, ?, ?)",
              {
                replacements: [
                  fname,
                  lname,
                  username,
                  gender,
                  email,
                  hashedPassword,
                ],
              }
            );
            if (result) {
              response("inserted");
            } else {
              response("insertFailed");
            }
          } else {
            response("insertFailed");
          }
        }
      }
    }
  );
  socket.on("login", async (email, password, response) => {
    const [result] = await sequelize.query(
      "SELECT person_email, person_username, person_password FROM person WHERE (person_email = ? OR person_username = ?)",
      {
        replacements: [email, email, password],
      }
    );
    if (result.length > 0) {
      const hashedPassword = result[0].person_password;
      const isPasswordValid = await bcrypt.compare(password, hashedPassword);
      if (isPasswordValid) {
        const token = jwt.sign(
          { username: email, password: password },
          "secretkey",
          { expiresIn: "1h" }
        );
        response({ status: "loginSuccess", token: token });
      } else {
        response("incorrectPassword");
      }
    } else {
      response("userNotFound");
    }
  });
  socket.on("requestIdstore", async (userId, response) => {
    const [resultStoreId] = await sequelize.query(
      "SELECT * FROM store WHERE person_id = ?",
      {
        replacements: [userId],
      }
    );
    if (resultStoreId && resultStoreId.length > 0) {
      const storeId = resultStoreId[0].store_id;
      if (resultStoreId.length > 0) {
        response({ storeId: storeId });
      }
    }
  });
  socket.on("requestDataMystore", async (userId, storeId, response) => {
    if (storeId) {
      const [resultMystore] = await sequelize.query(sqlSelMystore, {
        replacements: [userId, storeId],
      });
      if (resultMystore) {
        response({ dataMystore: resultMystore });
      }
    }
  });
  socket.on("requestDataPrivate", async (userId, response) => {
    const [result] = await sequelize.query(
      "SELECT * FROM person WHERE person_id = ?",
      {
        replacements: [userId],
      }
    );
    response({
      fname: result[0].person_fname,
      lname: result[0].person_lname,
      email: result[0].person_email,
      image: result[0].person_image,
      username: result[0].person_username,
      like: result[0].person_like,
      view: result[0].person_view,
      coin: result[0].person_coin,
    });
  });
  socket.on("reqStore", async (data, res) => {
    if (data.userId) {
      const [selStoreResult] = await sequelize.query(
        `SELECT * FROM store WHERE person_id = ?`,
        {
          replacements: [data.userId],
        }
      );
      if (selStoreResult) {
        res(selStoreResult[0]);
      }
    }
  });
  socket.on("onLike", async (shopId, userId, response) => {
    // ประกาศตัวแปร result ไว้ข้างนอก

    const [countResult] = await sequelize.query(
      `SELECT COUNT(*) as count FROM likedshops WHERE person_id = ? AND store_id = ?;`,
      {
        replacements: [userId, shopId],
      }
    );

    // ตรวจสอบค่าผลลัพธ์
    if (countResult && countResult[0].count > 0) {
      // หากมีการกดใจร้านแล้ว ให้ลบการกดใจ
      const [result] = await sequelize.query(
        `DELETE FROM likedshops WHERE person_id = ? AND store_id = ?`,
        {
          replacements: [userId, shopId],
        }
      );
      if (result) {
        const [resultStoreAllAndLike] = await sequelize.query(
          sqlSelStoretAllAndLike,
          {
            replacements: [userId],
          }
        );
        const [resultStoreAllLike] = await sequelize.query(sqlSelStoreAllLike, {
          replacements: [userId],
        });
        const [resultMystore] = await sequelize.query(sqlSelMystore, {
          replacements: [userId, shopId],
        });

        if (resultStoreAllAndLike && resultStoreAllLike) {
          // ส่งข้อมูลร้านพร้อมสถานะการกดใจ
          response({
            resDataStoreAll: resultStoreAllAndLike,
            resDataStoreAllLike: resultStoreAllLike,
            resDataLikeInStore: resultMystore,
          });
        }
      }
    } else {
      // หากยังไม่มีการกดใจร้าน ให้เพิ่มการกดใจ
      const [result] = await sequelize.query(
        `INSERT INTO likedshops (person_id, store_id, likeshops_date) VALUES(?, ?, ?)`,
        {
          replacements: [userId, shopId, formattedDate],
        }
      );
      if (result) {
        const [resultStoreAllAndLike] = await sequelize.query(
          sqlSelStoretAllAndLike,
          {
            replacements: [userId],
          }
        );
        const [resultStoreAllLike] = await sequelize.query(sqlSelStoreAllLike, {
          replacements: [userId],
        });
        const [resultMystore] = await sequelize.query(sqlSelMystore, {
          replacements: [userId, shopId],
        });

        if (resultStoreAllAndLike.length > 0 && resultStoreAllLike.length > 0) {
          // ส่งข้อมูลร้านพร้อมสถานะการกดใจ
          response({
            resDataStoreAll: resultStoreAllAndLike,
            resDataStoreAllLike: resultStoreAllLike,
            resDataLikeInStore: resultMystore,
          });
        }
      }
    }
  });

  socket.on(
    "createStore",
    async (userId, inputName, inputDetail, nameImg, response) => {
      try {
        const [result] = await sequelize.query(
          "INSERT INTO store (store_name, store_detail, store_image, store_creationdate ,person_id) VALUES (?, ?, ?, ?, ?)",
          {
            replacements: [
              inputName,
              inputDetail,
              nameImg,
              formattedDate,
              userId,
            ],
          }
        );

        if (result) {
          response({ status: "createSuccess" });
          const [resultStoreAllAndLike] = await sequelize.query(
            sqlSelStoretAllAndLike,
            {
              replacements: [userId],
            }
          );

          if (resultStoreAllAndLike) {
            // ส่งข้อมูลร้านพร้อมสถานะการกดใจ
            io.emit("resDataStoreAll", {
              resDataStoreAll: resultStoreAllAndLike,
            });
          }
        } else {
          response({ status: "error" });
        }
      } catch (error) {
        console.error("Error creating store:", error);
        response({ status: "error", message: error.message });
      }
    }
  );
  socket.on('reqComments', async (data)=>{
    if(data){
      const [resultComments] = await sequelize.query(sqlSelComments, {
        replacements: [data.storeId],
      });
      if (resultComments.length > 0) {
        socket.emit("resComments", { comments: resultComments });
      }
    }
  })
  socket.on("addComment", async (data) => {
    const [resultAddCm] = await sequelize.query(
      "INSERT INTO comments (store_id, person_id, comment_data, comment_like, comment_dislike, comment_datetime) VALUES (?, ?, ?, ?, ?, ?)",
      {
        replacements: [
          data.storeId,
          data.userId,
          data.inputComment,
          0,
          0,
          formattedDate,
        ],
      }
    );
    
    if (resultAddCm) {
      const [resultComments] = await sequelize.query(sqlSelComments, {
        replacements: [data.storeId],
      });
      if (resultComments.length > 0) {
        socket.emit("resComments", { comments: resultComments });
      }
    }
  });



  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
