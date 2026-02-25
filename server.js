console.log("PROFILE ROUTE VERSION LOADED");

const express = require("express");
const pool = require("./db"); 

async function ensureTables() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(50) NOT NULL,
      display_name VARCHAR(255),

      credit_balance DECIMAL DEFAULT 0,
      earnings_balance DECIMAL DEFAULT 0,

      audio_rate DECIMAL DEFAULT 0,
      video_rate DECIMAL DEFAULT 0,
      message_rate DECIMAL DEFAULT 0,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      caller_id INTEGER REFERENCES users(id),
      host_id INTEGER REFERENCES users(id),
      call_type VARCHAR(20),
      rate_per_minute DECIMAL,
      pre_authorized_amount DECIMAL,
      started_at TIMESTAMP,
      ended_at TIMESTAMP,
      status VARCHAR(20)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS calls (
      id SERIAL PRIMARY KEY,
      caller_id INTEGER REFERENCES users(id),
      host_id INTEGER REFERENCES users(id),
      duration INTEGER,
      rate_per_minute DECIMAL,
      total_cost DECIMAL,
      call_type VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_earnings (
      id SERIAL PRIMARY KEY,
      call_id INTEGER REFERENCES calls(id),
      commission_amount DECIMAL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("All tables ensured.");
}

async function startServer() {
  await ensureTables();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

const app = express();
const PORT = process.env.PORT || 3000;

const bcrypt = require("bcrypt"); //for password hashing
const jwt = require("jsonwebtoken"); //for token generation and verification

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "Token missing" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, "supersecretkey", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.user = user;
    next();
  });
};

// Middleware to read JSON
app.use(express.json());

// Health check route
app.get("/health", (req, res) => {
  res.json({ status: "Backend running successfully" });
});

const http = require("http");
const { Server } = require("socket.io");

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});


io.on("connection", (socket) => {
  console.log("New socket connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});




// Test database connection
app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ success: true, time: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Registration route
app.post("/register", async (req, res) => {
  const { email, password, role, display_name } = req.body;

  try {
    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password, role, display_name)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, role, display_name, credit_balance, earnings_balance`,
      [email, hashedPassword, role, display_name]
    );

    res.json({
      success: true,
      user: result.rows[0],
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      "supersecretkey",
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        display_name: user.display_name
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Protected route to get user profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, role, display_name, credit_balance, earnings_balance FROM users WHERE id = $1",
      [req.user.userId]
    );

    res.json({
      success: true,
      profile: result.rows[0],
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//create role middleware
const authorizeRole = (requiredRole) => {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).json({
        success: false,
        message: "Access denied: insufficient role"
      });
    }
    next();
  };
};


// Caller-only route
app.get("/caller/dashboard",
  authenticateToken,
  authorizeRole("CALLER"),
  (req, res) => {
    res.json({ message: "Welcome Caller" });
  }
);

// Host-only route
app.get("/host/dashboard",
  authenticateToken,
  authorizeRole("HOST"),
  (req, res) => {
    res.json({ message: "Welcome Host" });
  }
);

// Route for callers to top up their credit balance
app.post("/caller/topup", authenticateToken, async (req, res) => {
  console.log("Token payload:", req.user);
  if (req.user.role !== "CALLER") {
    return res.status(403).json({ message: "Only callers can top up" });
  }

  const { amount } = req.body;

  try {
    const result = await pool.query(
      `UPDATE users
       SET credit_balance = COALESCE(credit_balance, 0) + $1
       WHERE id = $2
       RETURNING credit_balance`,
      [amount, req.user.userId]
    );

    res.json({
      success: true,
      new_balance: result.rows[0].credit_balance
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Route for callers to start a call (deduct credit balance) // also log calls
app.post("/caller/start-call", authenticateToken, async (req, res) => {
  const callerId = req.user.id;

  if (req.user.role !== "CALLER") {
    return res.status(403).json({ message: "Only callers can start calls" });
  }

  const { hostId, callType } = req.body;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1️⃣ Validate call type
    if (!["audio", "video", "message"].includes(callType)) {
  await client.query("ROLLBACK");
  return res.status(400).json({ message: "Invalid call type" });
}

    // 2️⃣ Get caller balance
    const callerResult = await client.query(
      "SELECT credit_balance FROM users WHERE id = $1",
      [req.user.userId]
    );

    const callerBalance = parseFloat(callerResult.rows[0].credit_balance);

    // 3️⃣ Get host rates
    const hostResult = await client.query(
      `SELECT audio_rate, video_rate, message_rate
       FROM users
       WHERE id = $1 AND role = 'HOST'`,
      [hostId]
    );

    if (hostResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Invalid host" });
    }

    // 4️⃣ Determine rate
    let ratePerMinute;

    if (callType === "audio") {
      ratePerMinute = parseFloat(hostResult.rows[0].audio_rate);
    } else if (callType === "video") {
      ratePerMinute = parseFloat(hostResult.rows[0].video_rate);
    } else if (callType === "message") {
      ratePerMinute = parseFloat(hostResult.rows[0].message_rate);
    }

    if (!ratePerMinute || ratePerMinute <= 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Host rate not configured" });
    }

    // 5️⃣ Minimum pre-authorisation (1 minute)
    const minimumRequired = ratePerMinute * 1;

    if (callerBalance < minimumRequired) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Insufficient balance for 1 minute" });
    }

    // 6️⃣ Lock caller balance
    await client.query(
      "UPDATE users SET credit_balance = credit_balance - $1 WHERE id = $2",
      [minimumRequired, req.user.userId]
    );

    // 7️⃣ Create session
    const sessionInsert = await client.query(
      `INSERT INTO sessions
   (caller_id, host_id, call_type, rate_per_minute, pre_authorized_amount, started_at, status)
   VALUES ($1, $2, $3, $4, $5, NOW(), 'ACTIVE')
   RETURNING id`,
      [
        req.user.userId,
        hostId,
        callType,
        ratePerMinute,
        ratePerMinute // pre-authorized 1 minute
      ]
    );

const sessionId = sessionInsert.rows[0].id;

    await client.query("COMMIT");

    res.json({
      success: true,
      sessionId,
      ratePerMinute,
      preAuthorized: minimumRequired
    });

  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});


// Route for callers to view their call history
app.get("/caller/calls", authenticateToken, async (req, res) => {
  if (req.user.role !== "CALLER") {
    return res.status(403).json({ message: "Access denied" });
  }

  const result = await pool.query(
    "SELECT * FROM calls WHERE caller_id = $1 ORDER BY created_at DESC",
    [req.user.userId]
  );

  res.json(result.rows);
});


//host can view their earnings and call history
app.get("/host/calls", authenticateToken, async (req, res) => {
  if (req.user.role !== "HOST") {
    return res.status(403).json({ message: "Access denied" });
  }

  const result = await pool.query(
    "SELECT * FROM calls WHERE host_id = $1 ORDER BY created_at DESC",
    [req.user.userId]
  );

  res.json(result.rows);
});

app.get("/host/earnings", authenticateToken, authorizeRole("HOST"), async (req, res) => {
  const result = await pool.query(
    "SELECT earnings_balance FROM users WHERE id = $1",
    [req.user.userId]
  );
  res.json(result.rows[0]);
});


// Route for hosts to set their rates (audio, video, messaging)
app.put("/host/rates", authenticateToken, async (req, res) => {
  if (req.user.role !== "HOST") {
    return res.status(403).json({ message: "Only hosts can set rates" });
  }

  const { audio_rate, video_rate, message_rate } = req.body;

  if (audio_rate <= 0 || video_rate <= audio_rate || message_rate < 0) {
    return res.status(400).json({ message: "Invalid rate configuration" });
  }

  try {
    await pool.query(
      `UPDATE users
       SET audio_rate = $1,
           video_rate = $2,
           message_rate = $3
       WHERE id = $4`,
      [audio_rate, video_rate, message_rate, req.user.userId]
    );

    res.json({ success: true, message: "Rates updated" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Route for callers to end a call (finalize billing, update balances, log call)
app.post("/caller/end-call", authenticateToken, async (req, res) => {

  console.log("END CALL ROUTE HIT");

  if (req.user.role !== "CALLER") {
    return res.status(403).json({ message: "Only callers can end calls" });
  }

  const { sessionId } = req.body;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1️⃣ Lock session row
    const sessionResult = await client.query(
      "SELECT * FROM sessions WHERE id = $1 FOR UPDATE",
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Invalid session" });
    }

    const session = sessionResult.rows[0];

    if (session.status !== "ACTIVE") {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Session already closed" });
    }

    if (session.caller_id !== req.user.userId) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Unauthorized session access" });
    }

    const endedAt = new Date();

    // 2️⃣ Calculate duration
    const durationMs = endedAt - new Date(session.started_at);
    const durationMinutes = Math.ceil(durationMs / 60000); // always round up

    const totalCost =
      durationMinutes * parseFloat(session.rate_per_minute);

    // 3️⃣ Get caller balance
    const callerResult = await client.query(
      "SELECT credit_balance FROM users WHERE id = $1 FOR UPDATE",
      [req.user.userId]
    );

    const callerBalance = parseFloat(callerResult.rows[0].credit_balance);

    const preAuthorized = parseFloat(session.pre_authorized_amount);
    const remainingToCharge = totalCost - preAuthorized;

    if (remainingToCharge > 0) {
      // Need to charge extra
      if (callerBalance < remainingToCharge) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          message: "Insufficient balance to settle call"
        });
      }

      await client.query(
        "UPDATE users SET credit_balance = credit_balance - $1 WHERE id = $2",
        [remainingToCharge, req.user.userId]
      );

    } else if (remainingToCharge < 0) {
      // Refund unused pre-authorization
      const refundAmount = Math.abs(remainingToCharge);

      await client.query(
        "UPDATE users SET credit_balance = credit_balance + $1 WHERE id = $2",
        [refundAmount, req.user.userId]
      );
    }

    // 5️⃣ Commission split
    const platformCommission = totalCost * 0.10;
    const hostEarning = totalCost - platformCommission;

    await client.query(
      "UPDATE users SET earnings_balance = earnings_balance + $1 WHERE id = $2",
      [hostEarning, session.host_id]
    );

    // 6️⃣ Insert call record
    const callInsert = await client.query(
      `INSERT INTO calls
       (caller_id, host_id, duration, rate_per_minute, total_cost, call_type)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [
        session.caller_id,
        session.host_id,
        durationMinutes,
        session.rate_per_minute,
        totalCost,
        session.call_type
      ]
    );

    const callId = callInsert.rows[0].id;

    // 7️⃣ Insert platform earnings
    await client.query(
      `INSERT INTO platform_earnings (call_id, commission_amount)
       VALUES ($1, $2)`,
      [callId, platformCommission]
    );

    // 8️⃣ Close session
    await client.query(
      `UPDATE sessions
       SET ended_at = $1,
           status = 'COMPLETED'
       WHERE id = $2`,
      [endedAt, sessionId]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      durationMinutes,
      totalCost,
      hostEarning,
      platformCommission
    });

  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});


app.get("/hosts", async (req, res) => {
  const result = await pool.query(
    "SELECT id, display_name, audio_rate, video_rate, message_rate FROM users WHERE role = 'HOST'"
  );
  res.json(result.rows);
});

app.get("/migrate-users", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS credit_balance DECIMAL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS earnings_balance DECIMAL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS audio_rate DECIMAL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS video_rate DECIMAL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS message_rate DECIMAL DEFAULT 0;
    `);

    res.json({ message: "Users table migrated successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get("/debug/users", async (req, res) => {
  const result = await pool.query(
    "SELECT id, email, role FROM users"
  );
  res.json(result.rows);
});