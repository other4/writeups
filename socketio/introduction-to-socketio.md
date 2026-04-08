---
title: "Introduction to Socket-io"
description: " A comprehensive guide to understanding Socket.io, enabling real-time, bidirectional, and event-based communication between web clients and servers."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com" ]
created: "2026-04-08"
updated: "2026-04-08"
thumbnail: "/images/socketiointro.png"
tags: [socketio, nodejs, web-sockets, backend]
keywords: ["What is Socket.io", "Real-time communication in Node.js", "Socket.io vs WebSockets tutorial"]
---

# Introduction to Socket.io: Building Real-Time Applications

Socket.io is a powerful library that enables real-time, bidirectional, and event-based communication between a client (usually a browser) and a server (Node.js).

![Socket.IO](/images/socketiointro.png)

## What is Socket.IO?

**Socket.IO** is a JavaScript library that enables **real-time, bidirectional communication** between a browser (client) and a server.
It is commonly used for:
- Chat applications   
- Live notifications    
- Multiplayer games    
- Live dashboards    
- Collaboration tools    

Socket.IO works on top of **WebSockets**, but adds:
- Automatic reconnection    
- Fallback transports (polling)    
- Rooms & namespaces    
- Event-based API

## How Socket.IO works (high level)

1. Client connects to server    
2. Server keeps the connection open    
3. Both sides send and receive **events** using `emit` and `on   
Communication is **event-driven**, not request/response like HTTP.---

## Installation and setup
### 1. Create a project
```bash
mkdir socketio-demo
cd socketio-demo
npm init -y
```

### 2. Install dependencies
```bash
npm install express socket.io
```

### Basic Server Setup (Node.js)
Create `server.js`:
```js
const express = require('express')
const http = require('http')
const { Server } = require('socket.io')

const app = express()
const server = http.createServer(app)
const io = new Server(server)

app.get('/', (req, res) => {
  res.send('Socket.IO server running')
})

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id)

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id)
  })
})

server.listen(3000, () => {
  console.log('Server listening on port 3000')
})
```

### Important parts
- `http.createServer(app)` is required    
- `io.on('connection')` runs **every time a client connects*    
- Each client gets a unique `socket.id    

### Basic Client Setup (Browser)
Create `index.html`:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Socket.IO Demo</title>
</head>
<body>
  <h1>Socket.IO Client</h1>

  <script src="/socket.io/socket.io.js"></script>
  <script>
    const socket = io()

    socket.on('connect', () => {
      console.log('Connected with id:', socket.id)
    })
  </script>
</body>
</html>
```

Serve this file from Express:
```js
app.use(express.static(__dirname))
```

Now open:
```
http://localhost:3000
```


## Socket.IO Functions and Their Uses
Socket.IO is a JavaScript library that enables real-time, bidirectional communication between clients and servers using WebSockets with fallbacks. Here are the main functions and their descriptions:
### Core Connection Functions

| Function | Description | Use Case |
|----------|-------------|----------|
| **`io()`** | Initializes and connects a Socket.IO client to a server. | Establishing a connection from the client side. |
| **`io.connect()`** | Alternative method to establish a connection (older syntax). | Legacy code or explicit connection establishment. |
| **`disconnect()`** | Closes the connection between client and server. | Cleaning up resources or logging out users. |

### Event Emission Functions
#### Sending Events
**`emit(eventName, data, callback)`** — Sends an event from client to server or server to client.
- **Parameters:**
  - `eventName` (string): The name of the event
  - `data` (any): The data to send (object, string, number, etc.)
  - `callback` (function): Optional acknowledgment function called when the receiver processes the event
- **Use Cases:** Sending user actions, messages, or custom data in real-time.

#### Receiving Events

**`on(eventName, callback)`** — Listens for incoming events and executes a callback when received.
- **Parameters:**
  - `eventName` (string): The event to listen for
  - `callback` (function): Function executed when the event arrives, receives event data as parameter
- **Use Cases:** Handling incoming messages, notifications, or server updates.

**`once(eventName, callback)`** — Similar to `on()`, but the listener only fires once, then automatically removes itself.
- **Use Cases:** Handling one-time events like initial authentication or connection confirmations.

### Event Management Functions
**`off(eventName, callback)`** — Removes a specific event listener.
- **Use Cases:** Cleaning up listeners to prevent memory leaks or duplicate handlers.
**`removeAllListeners(eventName)`** — Removes all listeners for a specific event (or all events if no parameter provided).
- **Use Cases:** Resetting event handlers or disconnecting from a namespace.

### Namespace and Room Functions
**`of(namespaceName)`** — Accesses or creates a namespace for organizing events.
- **Use Cases:** Separating concerns (e.g., `/chat`, `/notifications`, `/gaming`).
**`join(roomName)`** — Adds a socket to a specific room.
- **Use Cases:** Grouping users (e.g., chat rooms, game lobbies).
**`leave(roomName)`** — Removes a socket from a room.
- **Use Cases:** User leaving a chat room or game.
**`to(roomName)`** — Targets a specific room for broadcasting (server-side).
- **Use Cases:** Sending messages only to users in a specific room.

### Broadcasting Functions
**`broadcast.emit(eventName, data)`** — Sends an event to all connected clients except the sender.
- **Use Cases:** Notifying other users of an action without echoing it back.

**`io.emit(eventName, data)`** — Sends an event to all connected clients (server-side).
- **Use Cases:** System-wide announcements or updates.

### Connection State Functions
**`connected`** — Boolean property indicating whether the socket is currently connected.
- **Use Cases:** Checking connection status before sending data.
**`id`** — Property containing the unique identifier for the socket.
- **Use Cases:** Identifying specific users or logging connection details.

### Error and Lifecycle Functions
```javascript
// Send to everyone
io.emit("message", data);

// Send to everyone except sender
socket.broadcast.emit("message", data);

// Send to specific room
io.to("roomName").emit("message", data);

// Send to specific room except sender
socket.to("roomName").emit("message", data);

// Send to only this socket
socket.emit("message", data);
```
---
## Socket.io Core Functions:

### 1. `io.on("connection")` - Main Connection Handler

#### What It Does
Listens for new client connections. This is the entry point for all Socket.io communication.

#### When It's Used
Every time a client connects to your server, this event fires.

#### Syntax
```javascript
io.on("connection", (socket) => {
  // Code runs when a client connects
});
```

#### Deep Explanation
```javascript
const io = require("socket.io")(server);

// This event fires EVERY TIME a client connects
io.on("connection", (socket) => {
  console.log("New user connected!");
  console.log(`Socket ID: ${socket.id}`); // Unique identifier for this connection
  console.log(`Total connected users: ${io.engine.clientsCount}`);

  // socket object represents the connected client
  // It has methods like emit, on, join, leave, etc.
});
```

#### Real-world Example: User Tracking
```javascript
const connectedUsers = new Map();

io.on("connection", (socket) => {
  // Store user information
  const user = {
    socketId: socket.id,
    userId: socket.handshake.auth.userId,
    connectedAt: new Date(),
    ip: socket.handshake.address
  };

  connectedUsers.set(socket.id, user);

  console.log(`👤 User ${user.userId} connected`);
  console.log(`📊 Total active users: ${connectedUsers.size}`);

  // Broadcast to all clients that someone joined
  io.emit("stats:userCount", {
    totalUsers: connectedUsers.size,
    newUser: user.userId
  });

  // Handle disconnect
  socket.on("disconnect", () => {
    connectedUsers.delete(socket.id);
    console.log(`👤 User disconnected. Total: ${connectedUsers.size}`);
    io.emit("stats:userCount", { totalUsers: connectedUsers.size });
  });
});
```

### 2. `socket.on()` - Listen for Client Events
#### What It Does
Listens for specific events sent from the client to the server.

#### When It's Used
When you want to receive data/messages from a connected client.

#### Syntax
```javascript
socket.on("eventName", (data) => {
  // Handle the event
});
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  // Listen for "message" event from client
  socket.on("message", (data) => {
    console.log("Received message:", data);
    // data = { text: "Hello", sender: "John" }
  });

  // Listen for multiple events
  socket.on("appointment:create", (appointmentData) => {
    console.log("New appointment:", appointmentData);
  });

  socket.on("user:typing", (isTyping) => {
    console.log("User is typing:", isTyping);
  });
});
```

#### Real-world Example: Appointment Creation

```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:create", (data) => {
    // data comes from client
    const appointment = {
      id: Date.now(),
      title: data.title,           // "Team Meeting"
      date: data.date,             // "2026-04-10"
      time: data.time,             // "14:30"
      duration: data.duration,     // 60 (minutes)
      createdBy: socket.userId,
      createdAt: new Date()
    };

    console.log(`📅 New appointment created: ${appointment.title}`);

    // Process the appointment (save to DB, validate, etc.)
    // Then send response back to client
  });
});
```

#### Client Side (How Client Sends Events)

```javascript
// Client-side code
const socket = io();

// Send event to server
socket.emit("appointment:create", {
  title: "Team Meeting",
  date: "2026-04-10",
  time: "14:30",
  duration: 60
});
```

### 3. `socket.emit()` - Send to Single Client

#### What It Does
Sends an event to ONLY the current connected client (private message).

#### When It's Used
When you want to send data to a specific user, not to everyone.

#### Syntax
```javascript
socket.emit("eventName", data);
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  // Send welcome message to ONLY this client
  socket.emit("welcome", {
    message: "Welcome to the appointment system!",
    socketId: socket.id
  });

  // Listen for login event
  socket.on("user:login", (userData) => {
    console.log(`User ${userData.name} logged in`);

    // Send confirmation ONLY to this user
    socket.emit("login:success", {
      message: "Login successful!",
      userId: userData.id,
      token: "jwt_token_here"
    });
  });
});
```

#### Real-world Example: Private Notification

```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:book", (appointmentData) => {
    // Validate and save appointment
    const appointment = {
      id: Date.now(),
      ...appointmentData
    };

    // Send SUCCESS message ONLY to this client
    socket.emit("appointment:bookingSuccess", {
      success: true,
      appointmentId: appointment.id,
      message: "Your appointment has been booked!",
      confirmationNumber: `APT-${appointment.id}`
    });

    // Send ERROR message ONLY to this client
    if (!appointmentData.title) {
      socket.emit("appointment:bookingError", {
        success: false,
        error: "Title is required",
        code: "INVALID_TITLE"
      });
    }
  });
});
```

#### Key Difference: emit vs broadcast
```javascript
// ❌ WRONG - Sends to everyone (including sender)
io.emit("message", data);

// ✅ CORRECT - Sends only to this specific client
socket.emit("message", data);

// ✅ CORRECT - Sends to everyone EXCEPT sender
socket.broadcast.emit("message", data);
```

### 4. `socket.broadcast.emit()` - Send to All Except Sender

#### What It Does
Sends an event to ALL connected clients EXCEPT the one who sent the message.

#### When It's Used
When you want to notify others about what a user did, but not send it back to them.

#### Syntax
```javascript
socket.broadcast.emit("eventName", data);
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  socket.on("user:statusChange", (status) => {
    // User changed status to "online", "away", "busy"
    
    console.log(`User status: ${status}`);

    // Notify ALL OTHER users (not this user)
    socket.broadcast.emit("user:statusChanged", {
      userId: socket.userId,
      userName: socket.userName,
      newStatus: status,
      changedAt: new Date()
    });

    // This user won't receive this event
    // Other users will see "John is now online"
  });
});
```

#### Real-world Example: Appointment Updates

```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:reschedule", (data) => {
    const updatedAppointment = {
      id: data.appointmentId,
      newDate: data.newDate,
      newTime: data.newTime,
      rescheduledBy: socket.userName
    };

    // Tell everyone EXCEPT the person who rescheduled
    socket.broadcast.emit("appointment:rescheduled", {
      appointment: updatedAppointment,
      message: `${socket.userName} rescheduled an appointment`
    });

    // Send confirmation to the person who rescheduled
    socket.emit("appointment:rescheduleSuccess", {
      appointmentId: data.appointmentId,
      newDate: data.newDate,
      newTime: data.newTime
    });
  });
});
```

### 5. `io.emit()` - Broadcast to Everyone

#### What It Does
Sends an event to ALL connected clients (including the sender).

#### When It's Used
System-wide announcements, notifications everyone needs to see.

#### Syntax
```javascript
io.emit("eventName", data);
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  // When someone logs in, tell EVERYONE
  socket.on("user:login", (userData) => {
    console.log(`${userData.name} logged in`);

    // Broadcast to ALL clients
    io.emit("user:loggedIn", {
      userId: userData.id,
      userName: userData.name,
      loginTime: new Date()
    });
    // Everyone sees "John logged in"
  });
});
```

#### Real-world Example: System Announcement
```javascript
io.on("connection", (socket) => {
  
  socket.on("admin:announcement", (data) => {
    // Only admin can send announcements
    if (socket.userRole !== "admin") {
      socket.emit("error", { message: "Unauthorized" });
      return;
    }

    console.log(`📢 Announcement: ${data.message}`);

    // Send to EVERYONE
    io.emit("notification:announcement", {
      title: data.title,
      message: data.message,
      priority: data.priority, // "high", "medium", "low"
      sentBy: "Admin",
      sentAt: new Date()
    });
  });
});
```

### 6. `socket.join()` - Add Socket to a Room

#### What It Does
Adds the current socket to a named group called a "room". Multiple sockets can be in the same room.

#### When It's Used
When you want to group users (e.g., all users in a meeting, all users viewing a calendar).

#### Syntax
```javascript
socket.join("roomName");
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  // Join a personal room for this user
  socket.join(`user:${socket.userId}`);
  // Now only this user's socket is in this room

  // Join a global room
  socket.join("appointments");
  // Now this socket is in the appointments room with others

  // Join a specific appointment room
  socket.on("appointment:join", (appointmentId) => {
    socket.join(`appointment:${appointmentId}`);
    console.log(`User joined appointment ${appointmentId}`);
  });
});
```

#### Real-world Example: Appointment Rooms
```javascript
io.on("connection", (socket) => {
  
  // When user views a specific appointment
  socket.on("appointment:view", (appointmentId) => {
    // Add this socket to a room for that appointment
    socket.join(`appointment:${appointmentId}`);
    
    console.log(`User ${socket.userId} viewing appointment ${appointmentId}`);

    // Tell others in this room that someone is viewing
    io.to(`appointment:${appointmentId}`).emit("appointment:userViewing", {
      appointmentId: appointmentId,
      viewedBy: socket.userName,
      viewCount: io.sockets.adapter.rooms.get(`appointment:${appointmentId}`).size
    });
  });

  // When user stops viewing
  socket.on("appointment:leave", (appointmentId) => {
    socket.leave(`appointment:${appointmentId}`);
    console.log(`User left appointment ${appointmentId}`);
  });
});
```

#### Multiple Rooms Example
```javascript
io.on("connection", (socket) => {
  const userId = socket.userId;
  const departmentId = socket.departmentId;

  // One socket can be in multiple rooms
  socket.join(`user:${userId}`);           // Personal room
  socket.join(`department:${departmentId}`); // Department room
  socket.join("appointments");              // Global appointments room
  socket.join("notifications");             // Notifications room

  console.log(`Socket joined 4 rooms`);
});
```

### 7. `socket.leave()` - Remove Socket from Room

#### What It Does
Removes the socket from a specific room.

#### When It's Used
When a user stops viewing something or logs out.

#### Syntax
```javascript
socket.leave("roomName");
```
#### Deep Explanation

```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:view", (appointmentId) => {
    socket.join(`appointment:${appointmentId}`);
  });

  socket.on("appointment:closeView", (appointmentId) => {
    // Remove from this room
    socket.leave(`appointment:${appointmentId}`);
    console.log(`User left appointment ${appointmentId}`);
  });

  // Automatic cleanup on disconnect
  socket.on("disconnect", () => {
    // Socket automatically leaves all rooms
    console.log(`User disconnected and left all rooms`);
  });
});
```

#### Real-world Example: Video Call Rooms
```javascript
io.on("connection", (socket) => {
  
  socket.on("call:join", (callId) => {
    socket.join(`call:${callId}`);
    
    // Notify others in the call
    io.to(`call:${callId}`).emit("call:userJoined", {
      userId: socket.userId,
      userName: socket.userName,
      participantCount: io.sockets.adapter.rooms.get(`call:${callId}`).size
    });
  });

  socket.on("call:leave", (callId) => {
    socket.leave(`call:${callId}`);
    
    io.to(`call:${callId}`).emit("call:userLeft", {
      userId: socket.userId,
      participantCount: io.sockets.adapter.rooms.get(`call:${callId}`).size
    });
  });
});
```

### 8. `io.to()`- Send to Specific Room

#### What It Does
Sends an event to all sockets in a specific room.

#### When It's Used
When you want to notify a group of users.

#### Syntax
```javascript
io.to("roomName").emit("eventName", data);
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:update", (data) => {
    const appointmentId = data.appointmentId;

    // Send update to everyone viewing this appointment
    io.to(`appointment:${appointmentId}`).emit("appointment:updated", {
      appointmentId: appointmentId,
      title: data.title,
      date: data.date,
      time: data.time
    });
  });
});
```

#### Real-world Example: Department Notifications
```javascript
io.on("connection", (socket) => {
  
  socket.on("department:announcement", (data) => {
    const departmentId = socket.departmentId;

    // Send to all users in this department
    io.to(`department:${departmentId}`).emit("notification:new", {
      title: data.title,
      message: data.message,
      departmentId: departmentId,
      sentBy: socket.userName
    });

    console.log(`Announcement sent to department ${departmentId}`);
  });
});
```


### 9. `socket.to()` - Send to Room Except Sender

#### What It Does
Sends to all sockets in a room EXCEPT the sender.

#### When It's Used
When you want to notify others in a group but not the person who triggered the event.

#### Syntax
```javascript
socket.to("roomName").emit("eventName", data);
```

#### Deep Explanation
```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:comment", (data) => {
    const appointmentId = data.appointmentId;

    // Send comment to others viewing this appointment (not the commenter)
    socket.to(`appointment:${appointmentId}`).emit("appointment:newComment", {
      appointmentId: appointmentId,
      comment: data.comment,
      commentedBy: socket.userName,
      timestamp: new Date()
    });

    // Send confirmation to the commenter
    socket.emit("comment:posted", {
      success: true,
      commentId: Date.now()
    });
  });
});
```

### Real-world Example: Real-time Collaboration
```javascript
io.on("connection", (socket) => {
  
  socket.on("appointment:edit", (data) => {
    const appointmentId = data.appointmentId;

    // Tell others in the room that this user is editing
    socket.to(`appointment:${appointmentId}`).emit("appointment:userEditing", {
      appointmentId: appointmentId,
      editingUser: socket.userName,
      field: data.field // "title", "date", "time"
    });
```

## Imports and Dependencies
```javascript
const express = require("express");
```
**Imports the Express framework**, which is a Node.js web server library used to handle HTTP requests and routing. It simplifies building REST APIs.
```javascript
const http = require("http");
```
**Imports Node.js's built-in HTTP module**, which creates the underlying HTTP server. Socket.io needs this to work properly (it requires an HTTP server instance, not just Express).
```javascript
const { Server } = require("socket.io");
```
**Imports the Socket.io Server class** using destructuring. Socket.io enables real-time bidirectional communication between clients and server using WebSockets.
```javascript
const connectDB = require("./config/db");
```
**Imports the database connection function** from your config folder. This function likely connects your app to MongoDB (or another database) when called.

### Initialize Express App

```javascript
const app = express();
```
**Creates an Express application instance**. This `app` object is used to define routes, middleware, and configure the server behavior.

```javascript
app.use(express.json());
```
**Adds middleware that parses incoming JSON requests**. When a client sends a POST/PUT request with JSON data, this middleware automatically converts the request body from JSON text into a JavaScript object that you can access via `req.body`.

### Database Connection

```javascript
connectDB();
```
**Calls the database connection function** to establish a connection to your database when the server starts. This happens asynchronously, so the server may start before the database is fully connected.

### Create HTTP Server and Socket.io Instance

```javascript
const server = http.createServer(app);
```
**Creates an HTTP server** and passes the Express `app` to it. This wraps Express inside an HTTP server, which is required for Socket.io to work. Without this, Socket.io cannot attach to Express.

```javascript
const io = new Server(server, { cors: { origin: "*" } });
```
**Creates a Socket.io Server instance** and attaches it to the HTTP server. The `cors` option allows **cross-origin requests from any domain** (`"*"`), which is useful for development but should be restricted in production for security.

### Middleware: Inject Socket.io into Requests

```javascript
app.use((req, res, next) => {
  req.io = io;
  next();
});
```
**Custom middleware that makes Socket.io accessible in your route handlers**. 

- `req.io = io` — Attaches the Socket.io instance to every request object
- `next()` — Passes control to the next middleware/route handler

This allows you to use `req.io.emit()` or `req.io.to().emit()` inside your route handlers to send real-time messages to connected clients.

### Load Socket.io Events

```javascript
require("./socket/socket")(io);
```
**Imports and initializes your Socket.io event handlers** from the `./socket/socket.js` file. You pass the `io` instance to this file so it can define event listeners like `io.on("connection", ...)` and handle real-time communication.

### Define Routes

```javascript
app.use("/api/auth", require("./routes/authRoutes"));
```
**Mounts authentication routes** at the `/api/auth` path. Any request to `/api/auth/*` will be handled by your `authRoutes` file (e.g., login, signup, logout).

```javascript
app.use("/api/appointments", require("./routes/appointmentRoutes"));
```
**Mounts appointment routes** at the `/api/appointments` path. Requests like `POST /api/appointments` or `GET /api/appointments/:id` are handled here.

### Start the Server

```javascript
server.listen(3000, () => console.log("Server running"));
```
**Starts the HTTP server** on port **3000**. The callback function logs a message when the server successfully starts. You can now access your API at `http://localhost:3000`.

### Summary Flow

1. **Setup** — Express app created, JSON parser added
2. **Database** — Connection initiated
3. **Real-time** — HTTP server and Socket.io created
4. **Integration** — Socket.io injected into requests for easy access
5. **Events** — Socket.io event handlers loaded
6. **Routes** — API endpoints registered
7. **Listen** — Server starts on port 3000



## Project Structure
```
appointment-scheduler/
├── server/
│   ├── config/
│   │   └── db.js
│   ├── models/
│   │   ├── User.js
│   │   └── Appointment.js
│   ├── routes/
│   │   ├── authRoutes.js
│   │   └── appointmentRoutes.js
│   ├── controllers/
│   │   ├── appointmentController.js
│   │   └── authController.js
│   ├── socket/
│   │   ├── socket.js (Main Socket.io setup)
│   │   ├── appointmentEvents.js (Appointment socket events)
│   │   └── notificationEvents.js (Notification socket events)
│   ├── middleware/
│   │   └── auth.js
│   ├── utils/
│   │   └── socketManager.js
│   └── server.js
├── client/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AppointmentForm.jsx
│   │   │   ├── AppointmentList.jsx
│   │   │   └── NotificationCenter.jsx
│   │   ├── socket/
│   │   │   └── socketClient.js
│   │   ├── App.jsx
│   │   └── index.js
│   └── package.json
├── package.json
└── .env
```

### Backend Setup

#### 1. server.js - Main Server File

```javascript
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
require("dotenv").config();
const connectDB = require("./config/db");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to database
connectDB();

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.io with CORS configuration
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3001",
    methods: ["GET", "POST"],
    credentials: true
  },
  // Enable compression for better performance
  serveClient: true,
  // Reconnection settings
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  reconnectionAttempts: 5
});

// Inject io into request object for route handlers
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Load Socket.io events
require("./socket/socket")(io);

// Routes
app.use("/api/auth", require("./routes/authRoutes"));
app.use("/api/appointments", require("./routes/appointmentRoutes"));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

process.on("unhandledRejection", (err) => {
  console.error("Unhandled rejection:", err);
  process.exit(1);
});
```

**Explanation:**
- **`http.createServer(app)`** — Creates an HTTP server that Express runs on. Socket.io needs this to establish WebSocket connections.
- **`new Server(server, { cors })`** — Initializes Socket.io on the HTTP server with CORS settings to allow cross-origin connections.
- **`app.use((req, res, next) => { req.io = io })`** — Middleware that attaches the Socket.io instance to every request. This allows route handlers to emit real-time events.
- **`require("./socket/socket")(io)`** — Loads Socket.io event handlers from a separate file, keeping code organized.

#### 2. `socket/socket.js` - Socket.io Core Setup

```javascript
// This is the main Socket.io configuration file
// It handles connections, authentication, and event routing

module.exports = (io) => {
  // Middleware to authenticate socket connections
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
      return next(new Error("Authentication token required"));
    }
    
    // Verify token (simplified - implement proper JWT verification)
    try {
      socket.userId = "user123"; // In real app, extract from token
      socket.userName = "John Doe";
      next();
    } catch (err) {
      next(new Error("Invalid token"));
    }
  });

  // Main connection event
  io.on("connection", (socket) => {
    console.log(`✅ User connected: ${socket.id}`);
    console.log(`   User ID: ${socket.userId}`);

    // Join user to a personal room for notifications
    // This allows sending messages to specific users
    socket.join(`user:${socket.userId}`);
    
    // Join a global appointments room for broadcast updates
    socket.join("appointments");

    // Broadcast user online status
    io.emit("user:online", {
      userId: socket.userId,
      userName: socket.userName,
      timestamp: new Date()
    });

    // Load appointment-related events
    require("./appointmentEvents")(io, socket);
    
    // Load notification-related events
    require("./notificationEvents")(io, socket);

    // Handle disconnection
    socket.on("disconnect", () => {
      console.log(`❌ User disconnected: ${socket.id}`);
      io.emit("user:offline", { userId: socket.userId });
    });

    // Handle connection errors
    socket.on("error", (error) => {
      console.error(`Socket error for ${socket.id}:`, error);
    });
  });
};
```

**Key Concepts Explained:**

- **`io.use()`** — Middleware that runs before connection is established. Used for authentication.
- **`socket.join()`** — Adds socket to a "room". Rooms are groups of sockets that can receive targeted messages.
  - `user:${socket.userId}` — Personal room for individual notifications
  - `appointments` — Global room for broadcast updates
- **`io.emit()`** — Broadcasts to ALL connected clients
- **`socket.on("disconnect")`** — Runs when a user disconnects

#### 3. `socket/appointmentEvents.js` - Appointment Real-time Events

```javascript
// This file handles all Socket.io events related to appointments
// Focus on real-time synchronization across multiple users

module.exports = (io, socket) => {
  
  // Event: User creates a new appointment
  socket.on("appointment:create", async (data) => {
    console.log(`📅 New appointment created by ${socket.userId}:`, data);

    const appointment = {
      id: Date.now(),
      title: data.title,
      date: data.date,
      time: data.time,
      duration: data.duration,
      createdBy: socket.userId,
      createdByName: socket.userName,
      status: "scheduled",
      createdAt: new Date()
    };

    // Save to database (simulated here)
    // await Appointment.create(appointment);

    // Emit to all connected clients in appointments room
    // This ensures everyone sees the new appointment immediately
    io.to("appointments").emit("appointment:created", {
      success: true,
      appointment: appointment,
      message: `${socket.userName} created a new appointment`
    });

    // Send confirmation to the creator
    socket.emit("appointment:createSuccess", {
      appointmentId: appointment.id,
      message: "Appointment created successfully"
    });
  });

  // Event: User updates an appointment
  socket.on("appointment:update", (data) => {
    console.log(`✏️ Appointment updated by ${socket.userId}:`, data);

    const updatedAppointment = {
      id: data.appointmentId,
      title: data.title,
      date: data.date,
      time: data.time,
      status: data.status,
      updatedBy: socket.userId,
      updatedAt: new Date()
    };

    // Broadcast update to all clients
    io.to("appointments").emit("appointment:updated", {
      appointment: updatedAppointment,
      message: `${socket.userName} updated an appointment`
    });

    // Send acknowledgment to the updater
    socket.emit("appointment:updateSuccess", {
      appointmentId: data.appointmentId
    });
  });

  // Event: User deletes an appointment
  socket.on("appointment:delete", (data) => {
    console.log(`🗑️ Appointment deleted by ${socket.userId}:`, data.appointmentId);

    // Broadcast deletion to all clients
    io.to("appointments").emit("appointment:deleted", {
      appointmentId: data.appointmentId,
      deletedBy: socket.userId,
      message: `${socket.userName} deleted an appointment`
    });
  });

  // Event: User requests all appointments (on page load)
  socket.on("appointment:getAll", (callback) => {
    console.log(`📋 ${socket.userId} requested all appointments`);

    // Simulated data - in real app, fetch from database
    const appointments = [
      {
        id: 1,
        title: "Team Meeting",
        date: "2026-04-10",
        time: "10:00",
        createdBy: "user1",
        status: "scheduled"
      },
      {
        id: 2,
        title: "Client Call",
        date: "2026-04-11",
        time: "14:00",
        createdBy: "user2",
        status: "scheduled"
      }
    ];

    // Send data back to the requesting client via callback
    callback({
      success: true,
      appointments: appointments
    });
  });

  // Event: User confirms attendance for an appointment
  socket.on("appointment:confirm", (data) => {
    console.log(`✅ ${socket.userId} confirmed appointment ${data.appointmentId}`);

    // Notify appointment creator
    io.to(`user:${data.creatorId}`).emit("appointment:confirmed", {
      appointmentId: data.appointmentId,
      confirmedBy: socket.userName,
      message: `${socket.userName} confirmed attendance`
    });

    // Broadcast to all in appointments room
    io.to("appointments").emit("appointment:attendeeConfirmed", {
      appointmentId: data.appointmentId,
      attendee: socket.userName
    });
  });

  // Event: Real-time search for appointments
  socket.on("appointment:search", (searchTerm, callback) => {
    console.log(`🔍 ${socket.userId} searching for:`, searchTerm);

    // Simulated search results
    const results = [
      { id: 1, title: "Team Meeting", date: "2026-04-10" }
    ];

    callback({
      results: results,
      count: results.length
    });
  });
};
```

**Key Socket.io Patterns Explained:**

- **`socket.on("event", (data) => {})`** — Listens for events from client
- **`io.to("room").emit()`** — Sends to all sockets in a specific room
- **`socket.emit()`** — Sends to only that specific socket (private message)
- **`callback()`** — Acknowledgment function (request-response pattern)

#### 4. `socket/notificationEvents.js` - Notification System

```javascript
// Handles real-time notifications and alerts
// Shows how to send targeted messages to specific users

module.exports = (io, socket) => {

  // Event: Send notification to specific user
  socket.on("notification:send", (data) => {
    console.log(`📬 Sending notification to ${data.recipientId}`);

    const notification = {
      id: Date.now(),
      type: data.type, // "appointment", "reminder", "message"
      title: data.title,
      message: data.message,
      sentBy: socket.userName,
      sentAt: new Date(),
      read: false
    };

    // Send to specific user's personal room
    // This is the KEY to sending messages to specific users
    io.to(`user:${data.recipientId}`).emit("notification:new", notification);

    // Also send acknowledgment to sender
    socket.emit("notification:sent", {
      recipientId: data.recipientId,
      notificationId: notification.id
    });
  });

  // Event: Broadcast appointment reminder to all attendees
  socket.on("appointment:sendReminder", (data) => {
    console.log(`⏰ Sending reminder for appointment ${data.appointmentId}`);

    const reminder = {
      appointmentId: data.appointmentId,
      title: data.appointmentTitle,
      time: data.appointmentTime,
      message: `Reminder: ${data.appointmentTitle} at ${data.appointmentTime}`,
      sentAt: new Date()
    };

    // Send to all attendees
    data.attendeeIds.forEach(attendeeId => {
      io.to(`user:${attendeeId}`).emit("notification:reminder", reminder);
    });
  });

  // Event: Mark notification as read
  socket.on("notification:markRead", (notificationId) => {
    console.log(`✓ Notification ${notificationId} marked as read`);

    // Update in database
    // await Notification.findByIdAndUpdate(notificationId, { read: true });

    // Broadcast update
    io.to(`user:${socket.userId}`).emit("notification:marked", {
      notificationId: notificationId,
      read: true
    });
  });

  // Event: Get unread notification count
  socket.on("notification:getUnreadCount", (callback) => {
    console.log(`📊 ${socket.userId} requesting unread count`);

    // Simulated - fetch from database in real app
    const unreadCount = 3;

    callback({
      unreadCount: unreadCount
    });
  });

  // Event: Broadcast system-wide notification
  socket.on("notification:broadcast", (data) => {
    // Only admins should be able to do this
    if (socket.userId !== "admin") {
      socket.emit("error", { message: "Unauthorized" });
      return;
    }

    console.log(`📢 Broadcasting system notification`);

    // Send to ALL connected clients
    io.emit("notification:system", {
      title: data.title,
      message: data.message,
      type: "system",
      sentAt: new Date()
    });
  });
};
```

**Notification Patterns:**

- **`io.to(`user:${userId}`).emit()`** — Sends to a specific user only
- **`io.emit()`** — Broadcasts to everyone (system notifications)
- **Rooms are powerful** — Use them to target groups without loops

#### 5. `models/Appointment.js` - Database Model

```javascript
const mongoose = require("mongoose");

const appointmentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ""
  },
  date: {
    type: Date,
    required: true
  },
  startTime: {
    type: String, // "14:30"
    required: true
  },
  duration: {
    type: Number, // in minutes
    default: 60
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  attendees: [{
    userId: mongoose.Schema.Types.ObjectId,
    status: {
      type: String,
      enum: ["pending", "confirmed", "declined"],
      default: "pending"
    }
  }],
  status: {
    type: String,
    enum: ["scheduled", "in-progress", "completed", "cancelled"],
    default: "scheduled"
  },
  location: String,
  meetingLink: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Appointment", appointmentSchema);
```

#### 6. `routes/appointmentRoutes.js` - REST API Routes

```javascript
const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth");

// GET all appointments
router.get("/", auth, (req, res) => {
  // Fetch from database
  res.json({ appointments: [] });
});

// POST create appointment
router.post("/", auth, (req, res) => {
  const { title, date, time, duration } = req.body;

  // Save to database
  const appointment = {
    id: Date.now(),
    title,
    date,
    time,
    duration,
    createdBy: req.user.id
  };
```
---