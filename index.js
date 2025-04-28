import express from "express";
import cors from "cors";
import { Pool } from "pg";
import bodyParser from "body-parser";
import env from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import { CronJob } from "cron";
import { DateTime } from "luxon";
import postgres from "postgres";
import { Console, log } from "console";
import { createClient } from "@supabase/supabase-js";

//import { format, addMinutes, parse, differenceInSeconds } from 'date-fns';
const app = express();
app.use(express.json());
const port = process.env.SERVER_PORT || 3000;
// Middleware
env.config();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "http://localhost:3001",
    credentials: true,
  })
);
app.use(express.static("public"));



const supabase=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_KEY);


// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   ssl: { rejectUnauthorized: true }
// });
// export { pool };


// const connectionString = process.env.DATABASE_URL;
// const sql = postgres(connectionString, {
//   ssl: { rejectUnauthorized: false }, // Required for Supabase
//   connection_timeout: 30,
// });
// console.log('DATABASE_URL:', process.env.DATABASE_URL);

// Nodemailer transporter for MailSend SMTP
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// JWT Secret Key
const jwtSecretKey = process.env.SECRET;

// Middleware to validate JWT token
const validateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied: No token provided" });
  }

  jwt.verify(token, jwtSecretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  });
};

//GET DATA
async function testConnection() {
  const {data, error}= await supabase.from('logindata').select('*');
  console.log(data);
  
}

await testConnection()


// // POST registration
// app.post('/register', async (req, res) => {
//   const { email, password, firstname, lastname } = req.body;
//   if (!email || !password || !firstname || !lastname) {
//     return res.status(400).json({
//       status: 'error',
//       error: 'Email, password, firstname, and lastname are required'
//     });
//   }

//   try{
//     const checkResult = await sql`SELECT * FROM logindata WHERE email = ${email}`;
//     if (checkResult.length > 0) {
//       return res.status(409).json({
//         status: 'error',
//         error: 'Email already registered'
//       });
//     }
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const result = await sql`
//       INSERT INTO logindata (email, password, firstname, lastname)
//       VALUES (${email}, ${hashedPassword}, ${firstname}, ${lastname})
//       RETURNING id, email, firstname, lastname
//     `;

//     // Send success response
//     res.status(201).json({
//       status: 'success',
//       message: 'User registered successfully',
//       user: result[0]
//     });
//   } catch (err) {
//     console.error('Error registering user:', err);
//     res.status(500).json({
//       status: 'error',
//       error: 'Failed to register user'
//     });
//   }
// });

app.post('/register', async (req, res) => {
  const { email, password, firstname, lastname } = req.body;
  if (!email || !password || !firstname || !lastname) {
    return res.status(400).json({
      status: 'error',
      error: 'Email, password, firstname, and lastname are required'
    });
  }

  try {
    // Check if email exists
    const { data: existingUser, error: checkError } = await supabase
      .from('logindata')
      .select('*')
      .eq('email', email);

    if (checkError) throw checkError;
    if (existingUser.length > 0) {
      return res.status(409).json({
        status: 'error',
        error: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const { data: newUser, error: insertError } = await supabase
      .from('logindata')
      .insert([
        { email, password: hashedPassword, firstname, lastname }
      ])
      .select('id, email, firstname, lastname')
      .single();

    if (insertError) throw insertError;

    // Send success response
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      user: newUser
    });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({
      status: 'error',
      error: 'Failed to register user'
    });
  }
});
// // POST login
// app.post("/login", async (req, res) => {
//   const { email, password } = req.body;
//   if (!email || !password) {
//     return res.status(400).json({ error: "Email and password are required" });
//   }

//   try {
//     const result = await db.query("SELECT * FROM logindata WHERE email = $1", [
//       email,
//     ]);
//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "User not found" });
//     }

//     const user = result.rows[0];
//     const isPasswordValid = await bcrypt.compare(password, user.password);
//     if (!isPasswordValid) {
//       return res.status(401).json({ error: "Incorrect password" });
//     }

//     const token = jwt.sign(
//       { userId: user.id, email: user.email },
//       jwtSecretKey,
//       { expiresIn: "1h" }
//     );
//     res.status(200).json({
//       success: true,
//       message: "Logged in successfully",
//       token,
//       firstname: user.firstname,
//       lastname: user.lastname,
//     });
//   } catch (err) {
//     console.error("Error logging in:", err);
//     res.status(500).json({ error: "Failed to log in" });
//   }
// });
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Fetch user by email
    const { data: user, error: fetchError } = await supabase
      .from('logindata')
      .select('*')
      .eq('email', email)
      .single();
    if (fetchError || !user) {
      return res.status(404).json({ error: "User not found" });
    }
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Incorrect password" });
    }
    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      jwtSecretKey,
      { expiresIn: "1h" }
    );
    // Send success response
    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      token,
      firstname: user.firstname,
      lastname: user.lastname,
    });
  } catch (err) {
    console.error("Error logging in:", err);
    res.status(500).json({ error: "Failed to log in" });
  }
});

// // GET pending tasks ( with completestatus = FALSE, currentstatus = FALSE)
// app.get("/tasks", validateToken, async (req, res) => {
//   try {
//     const result = await db.query(
//       "SELECT * FROM post WHERE user_id = $1 AND completestatus = FALSE AND currentstatus = FALSE ORDER BY timeofentry DESC",
//       [req.userId]
//     );
//     res.json(result.rows);
//   } catch (err) {
//     console.error("Error fetching pending tasks:", err);
//     res.status(500).json({ error: "Failed to fetch pending tasks" });
//   }
// });
app.get("/tasks", validateToken, async (req, res) => {
  try {
    const { data: tasks, error } = await supabase
      .from('post')
      .select('*')
      .eq('user_id', req.userId)
      .eq('completestatus', false)
      .eq('currentstatus', false)
      .order('timeofentry', { ascending: false });

    if (error) throw error;

    res.json(tasks);
  } catch (err) {
    console.error("Error fetching pending tasks:", err);
    res.status(500).json({ error: "Failed to fetch pending tasks" });
  }
});

// // GET completed tasks (with completestatus = TRUE, currentstatus = FALSE)
// app.get("/taskschange", validateToken, async (req, res) => {
//   try {
//     const result = await db.query(
//       "SELECT * FROM post WHERE user_id = $1 AND completestatus = TRUE AND currentstatus = FALSE ORDER BY timeofentry DESC",
//       [req.userId]
//     );
//     res.json(result.rows);
//   } catch (err) {
//     console.error("Error fetching completed tasks:", err);
//     res.status(500).json({ error: "Failed to fetch completed tasks" });
//   }
// });

app.get("/taskschange", validateToken, async (req, res) => {
  try {
    const { data: tasks, error } = await supabase
      .from('post')
      .select('*')
      .eq('user_id', req.userId)
      .eq('completestatus', true)
      .eq('currentstatus', false)
      .order('timeofentry', { ascending: false });

    if (error) throw error;

    res.json(tasks);
  } catch (err) {
    console.error("Error fetching completed tasks:", err);
    res.status(500).json({ error: "Failed to fetch completed tasks" });
  }
});

// // POST new task
// app.post("/tasks", validateToken, async (req, res) => {
//   const {
//     task,
//     type,
//     timeofentry,
//     completestatus,
//     remindertime,
//     currentstatus,
//   } = req.body;
//   if (!task || !type || !remindertime) {
//     return res
//       .status(400)
//       .json({ error: "Task, type, and remindertime are required" });
//   }

//   try {
//     const result = await db.query(
//       "INSERT INTO post (user_id, task, type, timeofentry, completestatus, remindertime, currentstatus) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
//       [
//         req.userId,
//         task,
//         type,
//         timeofentry,
//         completestatus,
//         remindertime,
//         currentstatus,
//       ]
//     );
//     res.status(201).json(result.rows[0]);
//   } catch (err) {
//     console.error("Error adding task:", err);
//     res.status(500).json({ error: "Failed to add task" });
//   }
// });

app.post("/tasks", validateToken, async (req, res) => {
  const {
    task,
    type,
    timeofentry,
    completestatus,
    remindertime,
    currentstatus,
  } = req.body;
  if (!task || !type || !remindertime) {
    return res
      .status(400)
      .json({ error: "Task, type, and remindertime are required" });
  }

  try {
    const { data: newTask, error } = await supabase
      .from('post')
      .insert([
        {
          user_id: req.userId,
          task,
          type,
          timeofentry,
          completestatus,
          remindertime,
          currentstatus,
        }
      ])
      .select('*')
      .single();

    if (error) throw error;

    res.status(201).json(newTask);
  } catch (err) {
    console.error("Error adding task:", err);
    res.status(500).json({ error: "Failed to add task" });
  }
});

// // PATCH task status (mark as done)
// app.patch("/tasks/:id", validateToken, async (req, res) => {
//   const { id } = req.params;
//   const { completestatus, currentstatus } = req.body;

//   try {
//     const result = await db.query(
//       "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
//       [completestatus, currentstatus, id, req.userId]
//     );
//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "Task not found or unauthorized" });
//     }
//     res.json(result.rows[0]);
//   } catch (err) {
//     console.error("Error updating task status:", err);
//     res.status(500).json({ error: "Failed to update task status" });
//   }
// });

app.patch("/tasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const { data: updatedTask, error } = await supabase
      .from('post')
      .update({ completestatus, currentstatus })
      .eq('id', id)
      .eq('user_id', req.userId)
      .select('*')
      .single();

    if (error) throw error;
    if (!updatedTask) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.json(updatedTask);
  } catch (err) {
    console.error("Error updating task status:", err);
    res.status(500).json({ error: "Failed to update task status" });
  }
});

// // PATCH task status (hide task)
// app.patch("/dtasks/:id", validateToken, async (req, res) => {
//   const { id } = req.params;
//   const { completestatus, currentstatus } = req.body;

//   try {
//     const result = await db.query(
//       "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
//       [completestatus, currentstatus, id, req.userId]
//     );
//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "Task not found or unauthorized" });
//     }
//     res.json(result.rows[0]);
//   } catch (err) {
//     console.error("Error updating task status:", err);
//     res.status(500).json({ error: "Failed to update task status" });
//   }
// });

// // PUT task content (edit task/type)
// app.put("/tasks/:id", validateToken, async (req, res) => {
//   const { id } = req.params;
//   const { editedtask, editedtype } = req.body;
//   if (!editedtask) {
//     return res.status(400).json({ error: "Task content is required" });
//   }

//   try {
//     const result = await db.query(
//       "UPDATE post SET task = $1, type = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
//       [editedtask, editedtype, id, req.userId]
//     );
//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "Task not found or unauthorized" });
//     }
//     res.json(result.rows[0]);
//   } catch (err) {
//     console.error("Error updating task:", err);
//     res.status(500).json({ error: "Failed to update task" });
//   }
// });


app.patch("/dtasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const { data: updatedTask, error } = await supabase
      .from('post')
      .update({ completestatus, currentstatus })
      .eq('id', id)
      .eq('user_id', req.userId)
      .select('*')
      .single();

    if (error) throw error;
    if (!updatedTask) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.json(updatedTask);
  } catch (err) {
    console.error("Error updating task status:", err);
    res.status(500).json({ error: "Failed to update task status" });
  }
});

// PUT task content (edit task/type)
app.put("/tasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { editedtask, editedtype } = req.body;
  if (!editedtask) {
    return res.status(400).json({ error: "Task content is required" });
  }

  try {
    const { data: updatedTask, error } = await supabase
      .from('post')
      .update({ task: editedtask, type: editedtype })
      .eq('id', id)
      .eq('user_id', req.userId)
      .select('*')
      .single();

    if (error) throw error;
    if (!updatedTask) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.json(updatedTask);
  } catch (err) {
    console.error("Error updating task:", err);
    res.status(500).json({ error: "Failed to update task" });
  }
});

// // PATCH completed task (undo)
// app.patch("/taskschange/:id", validateToken, async (req, res) => {
//   const { id } = req.params;
//   const { completestatus, currentstatus } = req.body;

//   try {
//     const result = await db.query(
//       "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
//       [completestatus, currentstatus, id, req.userId]
//     );
//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "Task not found or unauthorized" });
//     }
//     res.json(result.rows[0]);
//   } catch (err) {
//     console.error("Error undoing task:", err);
//     res.status(500).json({ error: "Failed to undo task" });
//   }
// });

app.patch("/taskschange/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const { data: updatedTask, error } = await supabase
      .from('post')
      .update({ completestatus, currentstatus })
      .eq('id', id)
      .eq('user_id', req.userId)
      .select('*')
      .single();

    if (error) throw error;
    if (!updatedTask) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.json(updatedTask);
  } catch (err) {
    console.error("Error undoing task:", err);
    res.status(500).json({ error: "Failed to undo task" });
  }
});
// //Get data for Reminders page (summary)
// app.get("/reminders", validateToken, async (req, res) => {
//   try {
//     const result = await db.query(
//       "SELECT COUNT(*) AS count, COUNT(*) FILTER(WHERE completestatus = false AND currentstatus = false) AS pendingcount FROM post WHERE user_id = $1",
//       [req.userId]
//     );
//     const count = parseInt(result.rows[0].count);
//     const pendingcount = parseInt(result.rows[0].pendingcount);
//     res.json({ count, pendingcount });
//   } catch (err) {
//     console.error("null", err);
//     res.status(500).json({ error: "Failed to fetch pending tasks" });
//   }
// });

app.get("/reminders", validateToken, async (req, res) => {
  try {
    const { data: tasks, error } = await supabase
      .from('post')
      .select('*')
      .eq('user_id', req.userId);

    if (error) throw error;

    const count = tasks.length;
    const pendingcount = tasks.filter(
      task => task.completestatus === false && task.currentstatus === false
    ).length;

    res.json({ count, pendingcount });
  } catch (err) {
    console.error("null", err);
    res.status(500).json({ error: "Failed to fetch pending tasks" });
  }
});

// //Global API to get count of users registered
// app.get("/usercount", async (req, res) => {
//   try {
//     const result = await db.query("SELECT * FROM logindata");
//     const usercount = parseInt(result.rows.length);
//     res.json({ usercount });
//   } catch (err) {
//     console.error("Error:", err);
//     res.status(500).json({ error: "Failed to fetch user count" });
//   }
// });

app.get("/usercount", async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('logindata')
      .select('*');

    if (error) throw error;

    const usercount = users.length;
    res.json({ usercount });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: "Failed to fetch user count" });
  }
});

// //Costamized API to get rows of values for Pie at Reminder page
// app.get("/reminderspie", validateToken, async (req, res) => {
//   try {
//     const { rows: [{ personalcount, familycount, workcount, groupactivitycount }] } = await db.query(
//       `SELECT
//         COUNT(*) FILTER (WHERE completestatus AND currentstatus AND type = 'Personal')::integer AS personalcount,
//         COUNT(*) FILTER (WHERE completestatus AND currentstatus AND type = 'Work')::integer AS workcount,
//         COUNT(*) FILTER (WHERE completestatus AND currentstatus AND type = 'Family')::integer AS familycount,
//         COUNT(*) FILTER (WHERE completestatus AND currentstatus AND type = 'Group Activity')::integer AS groupactivitycount
//       FROM post
//       WHERE user_id = $1`,
//       [req.userId]
//     );

//     res.json({ personalcount, familycount, workcount, groupactivitycount });
//     //console.log({ personalcount, familycount, workcount, groupactivitycount });
//   } catch (err) {
//     console.error('Error fetching reminders:', err);
//     res.status(500).json({ error: 'Failed to fetch reminders' });
//   }
// });

app.get("/reminderspie", validateToken, async (req, res) => {
  try {
    const { data: tasks, error } = await supabase
      .from('post')
      .select('*')
      .eq('user_id', req.userId)
      .eq('completestatus', true)
      .eq('currentstatus', true);

    if (error) throw error;

    const personalcount = tasks.filter(task => task.type === 'Personal').length;
    const familycount = tasks.filter(task => task.type === 'Family').length;
    const workcount = tasks.filter(task => task.type === 'Work').length;
    const groupactivitycount = tasks.filter(task => task.type === 'Group Activity').length;

    res.json({ personalcount, familycount, workcount, groupactivitycount });
  } catch (err) {
    console.error('Error fetching reminders:', err);
    res.status(500).json({ error: 'Failed to fetch reminders' });
  }
});


// Nodemailer transporter for MailSend SMTP
// const transporter = nodemailer.createTransport({
//   host: process.env.SMTP_HOST,
//   port: process.env.SMTP_PORT,
//   secure: false,
//   auth: {
//     user: process.env.SMTP_USER,
//     pass: process.env.SMTP_PASS,
//   },
// });
//Function to check and send reminders
// async function checkAndSendReminders() {
//   try{
//     const now =DateTime.now().setZone('Asia/Kolkata');
//     const reminderTimeLower = now.plus({ minutes: 14, seconds: 30 });
//     const reminderTimeUpper = now.plus({ minutes: 15, seconds: 30 });

//     // Query to JOIN the data and send to mailOptions
//     const query = `
//       SELECT p.remindertime, p.completestatus, p.type, p.task, l.email, l.firstname, l.lastname,
//              TO_TIMESTAMP(p.remindertime, 'DD/MM/YYYY, HH12:MI:SS AM') as parsed_time
//       FROM post p
//       JOIN logindata l ON p.user_id = l.id
//       WHERE p.completestatus = false
//       AND TO_TIMESTAMP(p.remindertime, 'DD/MM/YYYY, HH12:MI:SS AM') BETWEEN $1 AND $2
//     `;
//     const values = [
//       reminderTimeLower.toFormat('dd/MM/yyyy, hh:mm:ss a'),
//       reminderTimeUpper.toFormat('dd/MM/yyyy, hh:mm:ss a'),
//     ];
//     const res = await db.query(query, values);

//     if (!Array.isArray(res.rows)) {
//       console.error('Query result rows is not an array:', res.rows.length);
//       return;
//     }

//   if(res.rows.length > 0){
//     console.log(`Tasks found: ${res.rows.length}`);
//     for(const row of res.rows){
//       const mailOptions = {
//         //Customized mail for task reminder
//         from: process.env.SMTP_EMAIL,
//         to: row.email,
//         subject: 'Upcoming Task Reminder',
//         text: `Dear ${row.firstname} ${row.lastname},\n\nThis is a reminder for your task which is scheduled at ${row.remindertime}\n Type: ${row.type}\n Task: ${row.task}.\n Please complete it soon!\n\nBest regards,\nDaily task Tracker 🩷`,
//       };

//       await transporter.sendMail(mailOptions);
//       console.log(`Email sent to ${row.email}`);
//       }
//     }else {
//       //Console to check if tasks are not found
//       // console.log('No tasks found for reminder window', {
//       //   lower: reminderTimeLower.toFormat('dd/MM/yyyy, hh:mm:ss a'),
//       //   upper: reminderTimeUpper.toFormat('dd/MM/yyyy, hh:mm:ss a'),
//       // });
//     }
//   }catch(err){
//     console.error('Error in CheckAndSendReminers:',err);
//   }
// }

// const job = new CronJob('* * * * *', checkAndSendReminders, null, true, 'Asia/Kolkata');
// job.start();
// process.on('SIGINT', async () => {
//   job.stop();
//   await db.end();
//   console.log('Cron job stopped and database connection closed.');
//   process.exit(0);
// });

async function checkAndSendReminders() {
  try {
    const now = DateTime.now().setZone('Asia/Kolkata');
    const reminderTimeLower = now.plus({ minutes: 14, seconds: 30 });
    const reminderTimeUpper = now.plus({ minutes: 15, seconds: 30 });

    // Query to fetch tasks and user data
    const { data: tasks, error } = await supabase
      .from('post')
      .select(`
        remindertime,
        completestatus,
        type,
        task,
        logindata:logindata(email, firstname, lastname)
      `)
      .eq('completestatus', false)
      .gte('remindertime', reminderTimeLower.toFormat('dd/MM/yyyy, hh:mm:ss a'))
      .lte('remindertime', reminderTimeUpper.toFormat('dd/MM/yyyy, hh:mm:ss a'));

    if (error) throw error;

    if (tasks.length > 0) {
      //console.log(`Tasks found: ${tasks.length}`);
      for (const row of tasks) {
        const mailOptions = {
          // Customized mail for task reminder
          from: process.env.SMTP_EMAIL,
          to: row.logindata.email,
          subject: 'Upcoming Task Reminder',
          text: `Dear ${row.logindata.firstname} ${row.logindata.lastname},\n\nThis is a reminder for your task which is scheduled at ${row.remindertime}\n Type: ${row.type}\n Task: ${row.task}.\n Please complete it soon!\n\nBest regards,\nDaily task Tracker 🩷`,
        };

        await transporter.sendMail(mailOptions);
        //console.log(`Email sent to ${row.logindata.email}`);
      }
    } else {
      // Console to check if tasks are not found
      // console.log('No tasks found for reminder window', {
      //   lower: reminderTimeLower.toFormat('dd/MM/yyyy, hh:mm:ss a'),
      //   upper: reminderTimeUpper.toFormat('dd/MM/yyyy, hh:mm:ss a'),
      // });
    }
  } catch (err) {
    //console.error('Error in CheckAndSendReminders:', err);
  }
}

const job = new CronJob('* * * * *', checkAndSendReminders, null, true, 'Asia/Kolkata');
job.start();

process.on('SIGINT', async () => {
  job.stop();
  //console.log('Cron job stopped.');
  process.exit(0);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
