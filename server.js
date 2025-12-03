const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = "super-secret-for-inkle-assignment";
const MONGO_URL = process.env.MONGO_URL;

mongoose
  .connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((e) => console.error("Mongo error", e));

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    passwordHash: String,
    role: {
      type: String,
      enum: ["user", "admin", "owner"],
      default: "user",
    },
  },
  { timestamps: true }
);

const postSchema = new mongoose.Schema(
  {
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    content: String,
  },
  { timestamps: true }
);

const likeSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    post: { type: mongoose.Schema.Types.ObjectId, ref: "Post" },
  },
  { timestamps: true }
);

const followSchema = new mongoose.Schema(
  {
    follower: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    following: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const blockSchema = new mongoose.Schema(
  {
    blocker: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    blocked: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const activitySchema = new mongoose.Schema(
  {
    actor: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    type: String,
    targetUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    targetPost: { type: mongoose.Schema.Types.ObjectId, ref: "Post" },
    message: String,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);
const Like = mongoose.model("Like", likeSchema);
const Follow = mongoose.model("Follow", followSchema);
const Block = mongoose.model("Block", blockSchema);
const Activity = mongoose.model("Activity", activitySchema);

function signToken(user) {
  return jwt.sign(
    { id: user._id, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function isBlockedBy(authorId, viewerId) {
  if (!authorId || !viewerId) return false;
  const rel = await Block.findOne({
    blocker: authorId,
    blocked: viewerId,
  });
  return !!rel;
}

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing token" });

  const [, token] = header.split(" ");
  if (!token) return res.status(401).json({ error: "Invalid token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Auth required" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: "Name, email, password required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userCount = await User.countDocuments();
    const role = userCount === 0 ? "owner" : "user";

    const user = await User.create({ name, email, passwordHash, role });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok)
      return res.status(400).json({ error: "Invalid email or password" });

    const token = signToken(user);
    res.json({
      token,
      user: { id: user._id, name: user.name, role: user.role },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/me", authRequired, async (req, res) => {
  const user = await User.findById(req.user.id).select("-passwordHash");
  res.json(user);
});

app.post("/posts", authRequired, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: "Content required" });

    const post = await Post.create({
      content,
      author: req.user.id,
    });

    await Activity.create({
      actor: req.user.id,
      type: "POST_CREATED",
      targetPost: post._id,
      message: `${req.user.name} made a post`,
    });

    res.status(201).json(post);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to create post" });
  }
});

app.get("/posts", authRequired, async (req, res) => {
  try {
    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .populate("author", "name role");

    const visible = [];
    for (const post of posts) {
      const blocked = await isBlockedBy(post.author._id, req.user.id);
      if (!blocked) visible.push(post);
    }

    res.json(visible);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

app.delete(
  "/admin/posts/:id",
  authRequired,
  requireRole("admin", "owner"),
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.id).populate("author", "name");
      if (!post) return res.status(404).json({ error: "Post not found" });

      await Post.deleteOne({ _id: post._id });
      await Like.deleteMany({ post: post._id });

      await Activity.create({
        actor: req.user.id,
        type: "POST_DELETED",
        targetPost: post._id,
        message: `${req.user.name} deleted ${post.author.name}'s post`,
      });

      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to delete post" });
    }
  }
);

app.post("/posts/:id/like", authRequired, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate("author");
    if (!post) return res.status(404).json({ error: "Post not found" });

    const existing = await Like.findOne({
      user: req.user.id,
      post: post._id,
    });
    if (existing)
      return res.status(400).json({ error: "Already liked this post" });

    const like = await Like.create({
      user: req.user.id,
      post: post._id,
    });

    await Activity.create({
      actor: req.user.id,
      type: "POST_LIKED",
      targetPost: post._id,
      message: `${req.user.name} liked ${post.author.name}'s post`,
    });

    res.status(201).json(like);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to like post" });
  }
});

app.delete(
  "/admin/likes/:id",
  authRequired,
  requireRole("admin", "owner"),
  async (req, res) => {
    try {
      const like = await Like.findById(req.params.id).populate("user post");
      if (!like) return res.status(404).json({ error: "Like not found" });

      await Like.deleteOne({ _id: like._id });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to delete like" });
    }
  }
);

app.post("/users/:id/follow", authRequired, async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.user.id)
      return res.status(400).json({ error: "Cannot follow yourself" });

    const targetUser = await User.findById(targetId);
    if (!targetUser) return res.status(404).json({ error: "User not found" });

    const existing = await Follow.findOne({
      follower: req.user.id,
      following: targetId,
    });
    if (existing)
      return res.status(400).json({ error: "Already following this user" });

    const follow = await Follow.create({
      follower: req.user.id,
      following: targetId,
    });

    await Activity.create({
      actor: req.user.id,
      type: "FOLLOWED_USER",
      targetUser: targetId,
      message: `${req.user.name} followed ${targetUser.name}`,
    });

    res.status(201).json(follow);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to follow user" });
  }
});

app.post("/users/:id/block", authRequired, async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.user.id)
      return res.status(400).json({ error: "Cannot block yourself" });

    const target = await User.findById(targetId);
    if (!target) return res.status(404).json({ error: "User not found" });

    const existing = await Block.findOne({
      blocker: req.user.id,
      blocked: targetId,
    });
    if (existing)
      return res.status(400).json({ error: "Already blocked this user" });

    const block = await Block.create({
      blocker: req.user.id,
      blocked: targetId,
    });

    await Activity.create({
      actor: req.user.id,
      type: "BLOCKED_USER",
      targetUser: targetId,
      message: `${req.user.name} blocked ${target.name}`,
    });

    res.status(201).json(block);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to block user" });
  }
});

app.delete(
  "/admin/users/:id",
  authRequired,
  requireRole("admin", "owner"),
  async (req, res) => {
    try {
      const target = await User.findById(req.params.id);
      if (!target) return res.status(404).json({ error: "User not found" });

      await Post.deleteMany({ author: target._id });
      await Like.deleteMany({ user: target._id });
      await Follow.deleteMany({
        $or: [{ follower: target._id }, { following: target._id }],
      });
      await Block.deleteMany({
        $or: [{ blocker: target._id }, { blocked: target._id }],
      });

      await User.deleteOne({ _id: target._id });

      await Activity.create({
        actor: req.user.id,
        type: "USER_DELETED",
        targetUser: target._id,
        message: `${target.name} was deleted by ${
          req.user.role === "owner" ? "Owner" : "Admin"
        }`,
      });

      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to delete user" });
    }
  }
);

app.post(
  "/owner/users/:id/make-admin",
  authRequired,
  requireRole("owner"),
  async (req, res) => {
    try {
      const target = await User.findById(req.params.id);
      if (!target) return res.status(404).json({ error: "User not found" });

      target.role = "admin";
      await target.save();

      res.json({ success: true, user: target });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to make admin" });
    }
  }
);

app.post(
  "/owner/users/:id/remove-admin",
  authRequired,
  requireRole("owner"),
  async (req, res) => {
    try {
      const target = await User.findById(req.params.id);
      if (!target) return res.status(404).json({ error: "User not found" });

      target.role = "user";
      await target.save();

      res.json({ success: true, user: target });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Failed to remove admin" });
    }
  }
);

app.get("/feed", authRequired, async (req, res) => {
  try {
    const activities = await Activity.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .populate("actor", "name")
      .populate({
        path: "targetPost",
        populate: { path: "author", select: "name" },
      })
      .populate("targetUser", "name");

    const visible = [];
    for (const act of activities) {
      let authorId = null;

      if (act.targetPost && act.targetPost.author) {
        authorId = act.targetPost.author._id;
      } else if (act.actor) {
        authorId = act.actor._id;
      }

      if (authorId) {
        const blocked = await isBlockedBy(authorId, req.user.id);
        if (blocked) continue;
      }

      visible.push(act);
    }

    res.json(
      visible.map((a) => ({
        id: a._id,
        type: a.type,
        message: a.message,
        createdAt: a.createdAt,
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load feed" });
  }
});

app.get("/", (req, res) => {
  res.send("Inkle Backend Assignment API is running.");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
