import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import env from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import cron from 'node-cron';
import { CronJob } from "cron";
import { DateTime } from "luxon";
import { Console, log } from "console";
import { createClient } from "@supabase/supabase-js";
import morgan from "morgan";
import helmet from "helmet";

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(morgan("common"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  cors({
    origins: ["http://localhost:3000"],
  })
);

env.config();
const port = process.env.SERVER_PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  cors({
    origin: ["https://ddt-frontend-sand.vercel.app/"],
    credentials: true,
  })
);
app.use(express.static("public"));

const supabase=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_KEY);
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


// POST registration
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

// POST login
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
      console.log(fetchError);
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
      { expiresIn: "2h" }
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

// GET pending tasks ( with completestatus = FALSE, currentstatus = FALSE)
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

// GET completed tasks (with completestatus = TRUE, currentstatus = FALSE)
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

// POST new task
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

// PATCH task status (mark as done)
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

// PATCH task status (hide task)
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

// PATCH completed task (undo)
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
// GET data for Reminders page (summary)
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

// Global API to get count of users registered
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

// Costamized API to get rows of values for Pie at Reminder page
let lastCronExecution = null;
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


//Function to check and send reminders
async function checkAndSendReminders() {
  const now = DateTime.now().setZone('Asia/Kolkata');
  try {
    const reminderTimeLower = now.plus({ minutes: 14, seconds: 30 });
    const reminderTimeUpper = now.plus({ minutes: 15, seconds: 30 });

    console.log(`[${now.toISO()}] Checking tasks for reminder window:`, {
      lower: reminderTimeLower.toFormat('d/M/yyyy, h:mm:ss a'),
      upper: reminderTimeUpper.toFormat('d/M/yyyy, h:mm:ss a'),
    });

    const { data: tasks, error } = await supabase
      .from('post')
      .select(`
        remindertime,
        completestatus,
        type,
        task,
        logindata:logindata!user_id(email, firstname, lastname)
      `)
      .eq('completestatus', false)
      .not('remindertime', 'is', null)
      .filter('remindertime', 'in', `(
        SELECT remindertime 
        FROM post 
        WHERE TO_TIMESTAMP(remindertime, 'DD/M/YYYY, H:MM:SS pm') 
          BETWEEN TO_TIMESTAMP('${reminderTimeLower.toFormat('d/M/yyyy, h:mm:ss a')}', 'DD/M/YYYY, H:MM:SS pm') 
          AND TO_TIMESTAMP('${reminderTimeUpper.toFormat('d/M/yyyy, h:mm:ss a')}', 'DD/M/YYYY, H:MM:SS pm')
      )`);

    if (error) {
      console.error(`[${now.toISO()}] Supabase query error:`, JSON.stringify(error, null, 2));
      throw error;
    }

    if (tasks && tasks.length > 0) {
      console.log(`[${now.toISO()}] Tasks found: ${tasks.length}`);
      for (const row of tasks) {
        const mailOptions = {
          from: process.env.SMTP_EMAIL,
          to: row.logindata.email,
          subject: 'Upcoming Task Reminder',
          text: `Dear ${row.logindata.firstname} ${row.logindata.lastname},\n\nThis is a reminder for your task scheduled at ${row.remindertime}\nType: ${row.type}\nTask: ${row.task}.\nPlease complete it soon!\n\nBest regards,\nDaily Task Tracker 🩷`,
        };

        try {
          await transporter.sendMail(mailOptions);
          console.log(`[${now.toISO()}] Email sent to ${row.logindata.email}`);
        } catch (emailError) {
          console.error(`[${now.toISO()}] Failed to send email to ${row.logindata.email}:`, emailError.message);
        }
      }
    } else {
      console.log(`[${now.toISO()}] No tasks found for reminder window`, {
        lower: reminderTimeLower.toFormat('d/M/yyyy, h:mm:ss a'),
        upper: reminderTimeUpper.toFormat('d/M/yyyy, h:mm:ss a'),
      });
    }
  } catch (err) {
    console.error(`[${now.toISO()}] Error in checkAndSendReminders:`, err.message, err.stack);
  }
}
// Verify SMTP connection
transporter.verify((error, success) => {
  if (error) {
    console.error('SMTP connection error:', error);
    process.exit(1);
  } else {
    console.log('SMTP connection successful');
  }
});

// Schedule cron job
const cronJob = cron.schedule('*/1 * * * *', () => {
  lastCronExecution = DateTime.now().setZone('Asia/Kolkata');
  console.log(`[${lastCronExecution.toISO()}] Cron job triggered`);
  checkAndSendReminders();
}, {
  timezone: 'Asia/Kolkata',
});

// Log cron schedule
console.log('Cron job scheduled:', cronJob.options);


// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
