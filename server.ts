import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { db, DBUser, DBNote } from './src/server/db';
import {
  generateSalt,
  hashPassword,
  deriveEncryptionKey,
  encryptText,
  decryptText,
  generateSessionToken,
} from './src/server/crypto';

// Session layout in memory (derived encryption key is NEVER persisted to disk)
interface Session {
  token: string;
  userId: string;
  username: string;
  email: string;
  derivedKey: Buffer;
  expiresAt: number;
}

const sessions = new Map<string, Session>();
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

// Helper to parse cookies manually to avoid external middleware dependencies
function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    if (parts.length >= 2) {
      cookies[parts[0].trim()] = parts.slice(1).join('=').trim();
    }
  });
  return cookies;
}

// Session cleaner (runs every 1 hour to free memory of expired keys)
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Use JSON parser for request bodies
  app.use(express.json());

  // Security headers to prevent common web attacks (XSS, clickjacking, sniffers)
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Auth Middleware
  const requireAuth = (req: any, res: any, next: any) => {
    const cookies = parseCookies(req.headers.cookie);
    let token = cookies['session_token'];

    // If cookie is not present (often blocked in cross-origin sandboxed iframes),
    // we fallback to the Authorization Bearer header
    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[0] === 'Bearer' && parts[1]) {
        token = parts[1];
      }
    }

    if (!token) {
      return res.status(401).json({ success: false, error: 'Unauthorized: No session token provided' });
    }

    const session = sessions.get(token);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Unauthorized: Session invalid' });
    }

    if (session.expiresAt < Date.now()) {
      sessions.delete(token);
      return res.status(401).json({ success: false, error: 'Unauthorized: Session expired' });
    }

    // Refresh expiration on activity
    session.expiresAt = Date.now() + SESSION_DURATION_MS;
    req.session = session;
    next();
  };

  // --- API Routes ---

  // Register Endpoint
  app.post('/api/auth/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Missing username, email, or password' });
    }

    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Username must be at least 3 characters and password at least 6 characters',
      });
    }

    // Check existing
    if (db.getUserByEmail(email)) {
      return res.status(400).json({ success: false, error: 'Email is already registered' });
    }

    if (db.getUserByUsername(username)) {
      return res.status(400).json({ success: false, error: 'Username is already taken' });
    }

    try {
      const passwordSalt = generateSalt();
      const userSalt = generateSalt();
      const passwordHash = hashPassword(password, passwordSalt);

      const newUser: DBUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11),
        username,
        email,
        passwordHash,
        passwordSalt,
        userSalt,
        createdAt: new Date().toISOString(),
      };

      db.createUser(newUser);

      res.status(201).json({
        success: true,
        data: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          createdAt: newUser.createdAt,
        },
      });
    } catch (err: any) {
      console.error('Registration error:', err);
      res.status(500).json({ success: false, error: 'Internal server error during registration' });
    }
  });

  // Login Endpoint
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Missing email or password' });
    }

    try {
      const user = db.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }

      // Verify Password
      const computedHash = hashPassword(password, user.passwordSalt);
      if (computedHash !== user.passwordHash) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }

      // Derive symmetric key from user's password and individual userSalt
      const derivedKey = deriveEncryptionKey(password, user.userSalt);

      // Create secure session
      const token = generateSessionToken();
      const session: Session = {
        token,
        userId: user.id,
        username: user.username,
        email: user.email,
        derivedKey,
        expiresAt: Date.now() + SESSION_DURATION_MS,
      };

      sessions.set(token, session);

      // Set cookie - secure, HttpOnly, SameSite strict
      res.setHeader(
        'Set-Cookie',
        `session_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DURATION_MS / 1000}`
      );

      res.json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
          },
        },
      });
    } catch (err: any) {
      console.error('Login error:', err);
      res.status(500).json({ success: false, error: 'Internal server error during authentication' });
    }
  });

  // Logout Endpoint
  app.post('/api/auth/logout', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    let token = cookies['session_token'];

    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[0] === 'Bearer' && parts[1]) {
        token = parts[1];
      }
    }

    if (token) {
      sessions.delete(token);
    }

    res.setHeader('Set-Cookie', 'session_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Strict');
    res.json({ success: true, message: 'Logged out successfully' });
  });

  // Current User Session Check
  app.get('/api/auth/me', (req: any, res) => {
    const cookies = parseCookies(req.headers.cookie);
    let token = cookies['session_token'];

    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[0] === 'Bearer' && parts[1]) {
        token = parts[1];
      }
    }

    if (!token) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    const session = sessions.get(token);
    if (!session || session.expiresAt < Date.now()) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    res.json({
      success: true,
      data: {
        id: session.userId,
        username: session.username,
        email: session.email,
      },
    });
  });

  // --- Secure Notes Management (Authenticated, with Decryption/Encryption) ---

  // List all notes for the authenticated user
  app.get('/api/notes', requireAuth, (req: any, res) => {
    const session: Session = req.session;

    try {
      const dbNotes = db.getNotesByOwnerId(session.userId);

      // Decrypt note titles and contents in memory
      const decryptedNotes = dbNotes.map(n => {
        try {
          const decryptedTitle = decryptText(n.title, n.titleIv, session.derivedKey);
          const decryptedContent = decryptText(n.encryptedNote, n.iv, session.derivedKey);

          return {
            id: n.id,
            title: decryptedTitle,
            content: decryptedContent,
            createdAt: n.createdAt,
            raw: {
              title: n.title,
              content: n.encryptedNote,
              iv: n.iv,
              titleIv: n.titleIv,
            },
          };
        } catch (decryptErr) {
          // If decryption fails (e.g. incorrect key in memory, though session ensures correct key),
          // fallback to encrypted placeholder or filter out.
          return {
            id: n.id,
            title: '[Encrypted Title - Decryption Failure]',
            content: '[Encrypted Note Content - Decryption Failure]',
            createdAt: n.createdAt,
            raw: {
              title: n.title,
              content: n.encryptedNote,
              iv: n.iv,
              titleIv: n.titleIv,
            },
          };
        }
      });

      res.json({ success: true, data: decryptedNotes });
    } catch (err: any) {
      console.error('Fetch notes error:', err);
      res.status(500).json({ success: false, error: 'Internal server error while fetching notes' });
    }
  });

  // Create a note
  app.post('/api/notes', requireAuth, (req: any, res) => {
    const session: Session = req.session;
    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json({ success: false, error: 'Note title and content are required' });
    }

    try {
      // Encrypt the title and content
      const encryptedTitleResult = encryptText(title, session.derivedKey);
      const encryptedContentResult = encryptText(content, session.derivedKey);

      const newNote: DBNote = {
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11),
        title: encryptedTitleResult.encrypted,
        encryptedNote: encryptedContentResult.encrypted,
        iv: encryptedContentResult.iv,
        titleIv: encryptedTitleResult.iv,
        ownerId: session.userId,
        createdAt: new Date().toISOString(),
      };

      db.createNote(newNote);

      res.status(201).json({
        success: true,
        data: {
          id: newNote.id,
          title, // Return unencrypted for the client
          content,
          createdAt: newNote.createdAt,
          raw: {
            title: newNote.title,
            content: newNote.encryptedNote,
            iv: newNote.iv,
            titleIv: newNote.titleIv,
          },
        },
      });
    } catch (err: any) {
      console.error('Create note error:', err);
      res.status(500).json({ success: false, error: 'Internal server error while protecting and saving note' });
    }
  });

  // Edit/Update a note
  app.put('/api/notes/:id', requireAuth, (req: any, res) => {
    const session: Session = req.session;
    const { id } = req.params;
    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json({ success: false, error: 'Note title and content are required' });
    }

    try {
      const existing = db.getNoteById(id);
      if (!existing || existing.ownerId !== session.userId) {
        return res.status(404).json({ success: false, error: 'Note not found or unauthorized' });
      }

      // Re-encrypt the new title and content
      const encryptedTitleResult = encryptText(title, session.derivedKey);
      const encryptedContentResult = encryptText(content, session.derivedKey);

      const success = db.updateNote(
        id,
        encryptedTitleResult.encrypted,
        encryptedContentResult.encrypted,
        encryptedContentResult.iv,
        encryptedTitleResult.iv,
        session.userId
      );

      if (!success) {
        return res.status(500).json({ success: false, error: 'Failed to update database record' });
      }

      res.json({
        success: true,
        data: {
          id,
          title,
          content,
          createdAt: existing.createdAt,
          raw: {
            title: encryptedTitleResult.encrypted,
            content: encryptedContentResult.encrypted,
            iv: encryptedContentResult.iv,
            titleIv: encryptedTitleResult.iv,
          },
        },
      });
    } catch (err: any) {
      console.error('Update note error:', err);
      res.status(500).json({ success: false, error: 'Internal server error while modifying note' });
    }
  });

  // Delete a note
  app.delete('/api/notes/:id', requireAuth, (req: any, res) => {
    const session: Session = req.session;
    const { id } = req.params;

    try {
      const existing = db.getNoteById(id);
      if (!existing || existing.ownerId !== session.userId) {
        return res.status(404).json({ success: false, error: 'Note not found or unauthorized' });
      }

      const success = db.deleteNote(id, session.userId);
      if (!success) {
        return res.status(500).json({ success: false, error: 'Failed to delete note' });
      }

      res.json({ success: true, data: { id } });
    } catch (err: any) {
      console.error('Delete note error:', err);
      res.status(500).json({ success: false, error: 'Internal server error while removing note' });
    }
  });

  // Fallback check to view database status or secure state details (without displaying keys)
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'online',
      activeSessions: sessions.size,
      totalUsers: db.getUsers().length,
      mode: process.env.NODE_ENV || 'development',
    });
  });

  // Serve Frontend Assets
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SecureNotes Server] Running at http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start full-stack server:', err);
});
