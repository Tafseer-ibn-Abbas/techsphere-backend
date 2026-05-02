require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ─── MongoDB Connect ───────────────────────────────────────────────────────────
mongoose
   .connect(process.env.MONGO_URI, { family: 4 })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

// ─── Schemas ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" },
  createdAt: { type: Date, default: Date.now },
});

const applicationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  course: { type: String, required: true },
  message: String,
  resumeUrl: String,
  status: { type: String, default: "pending", enum: ["pending", "reviewed", "accepted", "rejected"] },
  createdAt: { type: Date, default: Date.now },
});

const courseSchema = new mongoose.Schema({
  title: String,
  description: String,
  duration: String,
  price: String,
  level: String,
  category: String,
  image: String,
  rating: { type: Number, default: 4.5 },
  enrolled: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const serviceSchema = new mongoose.Schema({
  title: String,
  description: String,
  icon: String,
  features: [String],
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Application = mongoose.model("Application", applicationSchema);
const Course = mongoose.model("Course", courseSchema);
const Service = mongoose.model("Service", serviceSchema);

// ─── Multer Setup (Resume Upload) ─────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const fs = require("fs");
    if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname.replace(/\s/g, "_"));
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["application/pdf", "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Only PDF/DOC/DOCX allowed"));
  },
});

// ─── Email Helper ──────────────────────────────────────────────────────────────
const sendEmail = async (to, subject, html) => {
  if (!process.env.EMAIL_USER || process.env.EMAIL_USER === "your_gmail@gmail.com") return;
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
  } catch (e) {
    console.log("Email error:", e.message);
  }
};

// ─── Auth Middleware ───────────────────────────────────────────────────────────
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

const adminMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin") return res.status(403).json({ error: "Admin only" });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });
    res.json({ message: "Registered successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Admin login check
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign({ id: "admin", name: "Admin", email, role: "admin" },
        process.env.JWT_SECRET, { expiresIn: "7d" });
      return res.json({ token, name: "Admin", role: "admin" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, name: user.name, email, role: user.role },
      process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, name: user.name, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  INTERNSHIP APPLICATION ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Submit application (with optional resume upload)
app.post("/api/apply", upload.single("resume"), async (req, res) => {
  try {
    const { name, email, course, message } = req.body;
    if (!name || !email || !course)
      return res.status(400).json({ error: "Name, email, and course are required" });

    const resumeUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const app_doc = await Application.create({ name, email, course, message, resumeUrl });

    // Notify admin
    await sendEmail(
      process.env.ADMIN_EMAIL,
      `New Internship Application - ${name}`,
      `<h2>New Application Received</h2>
       <p><b>Name:</b> ${name}</p>
       <p><b>Email:</b> ${email}</p>
       <p><b>Course:</b> ${course}</p>
       <p><b>Message:</b> ${message || "—"}</p>
       <p><b>Resume:</b> ${resumeUrl ? "Attached" : "Not provided"}</p>`
    );

    // Confirm to applicant
    await sendEmail(
      email,
      "Application Received - TechSphere",
      `<h2>Hi ${name}! 🎉</h2>
       <p>We've received your internship application for <b>${course}</b>.</p>
       <p>We'll review it and get back to you within <b>24–48 hours</b>.</p>
       <p>Best,<br/>TechSphere Team</p>`
    );

    res.json({ message: "Application submitted successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get("/api/courses", async (req, res) => {
  try {
    const { search, category } = req.query;
    let query = { isActive: true };
    if (search) query.title = { $regex: search, $options: "i" };
    if (category && category !== "all") query.category = category;
    const courses = await Course.find(query).sort({ createdAt: -1 });
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/services", async (req, res) => {
  try {
    const services = await Service.find({ isActive: true });
    res.json(services);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "TechSphere API running ✅", time: new Date() });
});

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Get all applications
app.get("/api/admin/applications", adminMiddleware, async (req, res) => {
  try {
    const { status } = req.query;
    let query = {};
    if (status && status !== "all") query.status = status;
    const apps = await Application.find(query).sort({ createdAt: -1 });
    res.json(apps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update application status
app.patch("/api/admin/applications/:id", adminMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const app_doc = await Application.findByIdAndUpdate(
      req.params.id, { status }, { new: true }
    );
    if (!app_doc) return res.status(404).json({ error: "Not found" });

    // Email applicant on status change
    if (status === "accepted") {
      await sendEmail(app_doc.email, "🎉 Congratulations! - TechSphere",
        `<h2>Congratulations ${app_doc.name}!</h2>
         <p>Your internship application for <b>${app_doc.course}</b> has been <b>accepted</b>!</p>
         <p>Our team will contact you shortly with next steps.</p>`);
    } else if (status === "rejected") {
      await sendEmail(app_doc.email, "Application Update - TechSphere",
        `<h2>Hi ${app_doc.name},</h2>
         <p>We regret to inform you that your application for <b>${app_doc.course}</b> was not selected this round.</p>
         <p>Feel free to apply again in the next batch!</p>`);
    }

    res.json(app_doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete application
app.delete("/api/admin/applications/:id", adminMiddleware, async (req, res) => {
  try {
    await Application.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all courses
app.get("/api/admin/courses", adminMiddleware, async (req, res) => {
  try {
    const courses = await Course.find().sort({ createdAt: -1 });
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Create course
app.post("/api/admin/courses", adminMiddleware, async (req, res) => {
  try {
    const course = await Course.create(req.body);
    res.json(course);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update course
app.put("/api/admin/courses/:id", adminMiddleware, async (req, res) => {
  try {
    const course = await Course.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(course);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete course
app.delete("/api/admin/courses/:id", adminMiddleware, async (req, res) => {
  try {
    await Course.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all services
app.get("/api/admin/services", adminMiddleware, async (req, res) => {
  try {
    const services = await Service.find().sort({ createdAt: -1 });
    res.json(services);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Create service
app.post("/api/admin/services", adminMiddleware, async (req, res) => {
  try {
    const service = await Service.create(req.body);
    res.json(service);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update service
app.put("/api/admin/services/:id", adminMiddleware, async (req, res) => {
  try {
    const service = await Service.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(service);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete service
app.delete("/api/admin/services/:id", adminMiddleware, async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Stats dashboard
app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  try {
    const [totalApps, pending, accepted, rejected, totalCourses, totalUsers] = await Promise.all([
      Application.countDocuments(),
      Application.countDocuments({ status: "pending" }),
      Application.countDocuments({ status: "accepted" }),
      Application.countDocuments({ status: "rejected" }),
      Course.countDocuments({ isActive: true }),
      User.countDocuments(),
    ]);
    res.json({ totalApps, pending, accepted, rejected, totalCourses, totalUsers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all users
app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Seed initial data
app.post("/api/admin/seed", adminMiddleware, async (req, res) => {
  try {
    const courseCount = await Course.countDocuments();
    if (courseCount === 0) {
      await Course.insertMany([
        { title: "Full Stack Web Development", description: "Master React, Node.js, MongoDB, and build real projects.", duration: "3 months", price: "PKR 25,000", level: "Beginner", category: "Web", image: "https://images.unsplash.com/photo-1627398242454-45a1465c2479?w=400", rating: 4.9, enrolled: 150 },
        { title: "UI/UX Design Masterclass", description: "Learn Figma, user research, prototyping and design systems.", duration: "2 months", price: "PKR 18,000", level: "Beginner", category: "Design", image: "https://images.unsplash.com/photo-1561070791-2526d30994b5?w=400", rating: 4.8, enrolled: 90 },
        { title: "Cyber Security", description: "Ethical hacking, penetration testing, and network security.", duration: "4 months", price: "PKR 35,000", level: "Intermediate", category: "Security", image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400", rating: 4.7, enrolled: 60 },
        { title: "Data Science & ML", description: "Python, Pandas, Machine Learning, and data visualization.", duration: "4 months", price: "PKR 40,000", level: "Intermediate", category: "Data", image: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=400", rating: 4.8, enrolled: 75 },
        { title: "Cloud Computing (AWS)", description: "AWS services, cloud architecture, and DevOps fundamentals.", duration: "3 months", price: "PKR 30,000", level: "Intermediate", category: "Cloud", image: "https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=400", rating: 4.6, enrolled: 45 },
        { title: "Artificial Intelligence", description: "Deep learning, NLP, computer vision, and AI project building.", duration: "5 months", price: "PKR 50,000", level: "Advanced", category: "AI", image: "https://images.unsplash.com/photo-1677442135703-1787eea5ce01?w=400", rating: 4.9, enrolled: 80 },
      ]);
    }

    const serviceCount = await Service.countDocuments();
    if (serviceCount === 0) {
      await Service.insertMany([
        { title: "Web Development", description: "Custom websites and web apps built with modern tech.", icon: "🌐", features: ["Responsive Design", "React/Next.js", "SEO Optimized", "Fast Delivery"] },
        { title: "Mobile App Development", description: "iOS and Android apps with React Native.", icon: "📱", features: ["Cross Platform", "React Native", "App Store Publish", "Push Notifications"] },
        { title: "UI/UX Design", description: "Beautiful, user-centered designs that convert.", icon: "🎨", features: ["Figma Prototypes", "User Research", "Design Systems", "Wireframing"] },
        { title: "Digital Marketing", description: "Grow your brand with data-driven marketing.", icon: "📈", features: ["SEO/SEM", "Social Media", "Content Strategy", "Analytics"] },
      ]);
    }

    res.json({ message: "Seed data added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 TechSphere Backend running on port ${PORT}`));
