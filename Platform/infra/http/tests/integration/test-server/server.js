const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

const app = express();
const HTTP_PORT = process.env.HTTP_PORT || 8080;
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // limit each IP to 1000 requests per windowMs
});
app.use('/api/', limiter);

// File upload handling with secure configuration for multer 2.x
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Create uploads directory if it doesn't exist
    const uploadDir = '/tmp/uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure filename to prevent path traversal
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${name}-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1 // Limit to 1 file per request
  },
  fileFilter: (req, file, cb) => {
    // Basic file type validation
    const allowedMimes = ['text/plain', 'application/json', 'image/jpeg', 'image/png', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// Request logging middleware for testing
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Basic HTTP methods testing
app.get('/api/test', (req, res) => {
  res.json({
    method: 'GET',
    message: 'GET request successful',
    timestamp: new Date().toISOString(),
    query: req.query,
    headers: req.headers
  });
});

app.post('/api/test', (req, res) => {
  res.status(201).json({
    method: 'POST',
    message: 'POST request successful',
    timestamp: new Date().toISOString(),
    body: req.body,
    headers: req.headers
  });
});

app.put('/api/test', (req, res) => {
  res.json({
    method: 'PUT',
    message: 'PUT request successful',
    timestamp: new Date().toISOString(),
    body: req.body,
    headers: req.headers
  });
});

app.delete('/api/test', (req, res) => {
  res.json({
    method: 'DELETE',
    message: 'DELETE request successful',
    timestamp: new Date().toISOString(),
    headers: req.headers
  });
});

// JSON endpoint
app.get('/api/json', (req, res) => {
  res.json({
    data: {
      users: [
        { id: 1, name: 'John Doe', email: 'john@example.com' },
        { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
      ],
      pagination: {
        page: 1,
        limit: 10,
        total: 2
      }
    },
    meta: {
      timestamp: new Date().toISOString(),
      request_id: Math.random().toString(36).substr(2, 9)
    }
  });
});

// Status code testing endpoints
app.get('/api/status/:code', (req, res) => {
  const statusCode = parseInt(req.params.code);
  
  if (statusCode < 100 || statusCode > 599) {
    return res.status(400).json({ error: 'Invalid status code' });
  }
  
  const responses = {
    200: { message: 'OK' },
    201: { message: 'Created', id: 123 },
    204: null,
    400: { error: 'Bad Request', details: 'Invalid request parameters' },
    401: { error: 'Unauthorized', message: 'Authentication required' },
    403: { error: 'Forbidden', message: 'Access denied' },
    404: { error: 'Not Found', message: 'Resource not found' },
    429: { error: 'Too Many Requests', retry_after: 60 },
    500: { error: 'Internal Server Error', message: 'Something went wrong' },
    502: { error: 'Bad Gateway', message: 'Upstream server error' },
    503: { error: 'Service Unavailable', message: 'Service temporarily unavailable' }
  };
  
  const response = responses[statusCode] || { message: `Status ${statusCode}` };
  
  if (statusCode === 204) {
    res.status(statusCode).send();
  } else {
    res.status(statusCode).json(response);
  }
});

// Headers testing
app.get('/api/headers', (req, res) => {
  res.json({
    received_headers: req.headers,
    custom_headers_test: {
      'x-custom-header': req.headers['x-custom-header'] || 'not-provided',
      'authorization': req.headers['authorization'] || 'not-provided',
      'user-agent': req.headers['user-agent'] || 'not-provided'
    }
  });
});

// Response headers testing
app.get('/api/response-headers', (req, res) => {
  res.set({
    'X-Custom-Response-Header': 'test-value',
    'X-API-Version': '1.0',
    'X-Request-ID': Math.random().toString(36).substr(2, 9),
    'Cache-Control': 'no-cache'
  });
  
  res.json({
    message: 'Check response headers',
    timestamp: new Date().toISOString()
  });
});

// Timeout simulation
app.get('/api/timeout/:seconds', (req, res) => {
  const seconds = parseInt(req.params.seconds) || 1;
  const maxSeconds = 30; // Prevent abuse
  
  const actualSeconds = Math.min(seconds, maxSeconds);
  
  setTimeout(() => {
    res.json({
      message: `Response after ${actualSeconds} seconds`,
      requested_delay: seconds,
      actual_delay: actualSeconds,
      timestamp: new Date().toISOString()
    });
  }, actualSeconds * 1000);
});

// Large response testing
app.get('/api/large/:size', (req, res) => {
  const sizeKB = parseInt(req.params.size) || 1;
  const maxSizeKB = 10 * 1024; // 10MB limit
  
  const actualSizeKB = Math.min(sizeKB, maxSizeKB);
  const data = 'A'.repeat(actualSizeKB * 1024);
  
  res.json({
    message: 'Large response',
    size_kb: actualSizeKB,
    data: data
  });
});

// File upload testing with error handling
app.post('/api/upload', (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      // Handle multer errors to prevent DoS
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ 
            error: 'File too large',
            message: 'File size exceeds 10MB limit'
          });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
          return res.status(413).json({ 
            error: 'Too many files',
            message: 'Only one file allowed per request'
          });
        }
        return res.status(400).json({ 
          error: 'Upload error',
          message: err.message
        });
      }
      
      // Handle other errors (like file type validation)
      if (err.message === 'Invalid file type') {
        return res.status(400).json({ 
          error: 'Invalid file type',
          message: 'Only text, JSON, and image files are allowed'
        });
      }
      
      // Log unexpected errors but don't expose details
      console.error('Upload error:', err);
      return res.status(500).json({ 
        error: 'Internal server error',
        message: 'File upload failed'
      });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    res.json({
      message: 'File uploaded successfully',
      file: {
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        filename: req.file.filename
      },
      timestamp: new Date().toISOString()
    });
  });
});

// Authentication simulation
app.get('/api/auth/bearer', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Bearer token required'
    });
  }
  
  const token = authHeader.substring(7);
  
  if (token === 'valid-token-123') {
    res.json({
      message: 'Authentication successful',
      user: { id: 1, username: 'testuser' },
      token: token
    });
  } else {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid token'
    });
  }
});

// Basic auth simulation
app.get('/api/auth/basic', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Test Realm"');
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Basic authentication required'
    });
  }
  
  const credentials = Buffer.from(authHeader.substring(6), 'base64').toString();
  const [username, password] = credentials.split(':');
  
  if (username === 'testuser' && password === 'testpass') {
    res.json({
      message: 'Authentication successful',
      user: { username: username }
    });
  } else {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid credentials'
    });
  }
});

// Content type testing
app.post('/api/content-types/json', (req, res) => {
  if (req.headers['content-type'] !== 'application/json') {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Content-Type must be application/json'
    });
  }
  
  res.json({
    message: 'JSON content received',
    received_data: req.body
  });
});

app.post('/api/content-types/form', (req, res) => {
  res.json({
    message: 'Form data received',
    received_data: req.body
  });
});

// Redirect testing
app.get('/api/redirect/:code/:times', (req, res) => {
  const statusCode = parseInt(req.params.code);
  const times = parseInt(req.params.times) || 1;
  
  if (times <= 0) {
    return res.json({
      message: 'Redirect chain completed',
      final_destination: true
    });
  }
  
  const nextUrl = `/api/redirect/${statusCode}/${times - 1}`;
  res.status(statusCode).location(nextUrl).json({
    message: `Redirecting ${times} more times`,
    next_url: nextUrl
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.url} not found`,
    timestamp: new Date().toISOString()
  });
});

// Start HTTP server
const httpServer = app.listen(HTTP_PORT, () => {
  console.log(`HTTP Test Server running on port ${HTTP_PORT}`);
  console.log(`Health check: http://localhost:${HTTP_PORT}/health`);
});

// Start HTTPS server if certificates exist
try {
  const httpsOptions = {
    key: fs.readFileSync('/app/certs/key.pem'),
    cert: fs.readFileSync('/app/certs/cert.pem')
  };
  
  const httpsServer = https.createServer(httpsOptions, app);
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`HTTPS Test Server running on port ${HTTPS_PORT}`);
    console.log(`HTTPS Health check: https://localhost:${HTTPS_PORT}/health`);
  });
} catch (error) {
  console.log('HTTPS server not started:', error.message);
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully');
  httpServer.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully');
  httpServer.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});
