const express = require('express');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

app.post('/test', [
  body('email').isEmail().normalizeEmail()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.json({ errors: errors.array() });
  }
  
  console.log('Original req.body.email:', req.body.email);
  const { email } = req.body;
  console.log('Destructured email:', email);
  
  res.json({ email, body: req.body });
  process.exit(0);
});

app.listen(8082, () => {
  console.log('Test server on 8082');
  console.log('Send POST to /test with {"email":"colinnebula@gmail.com"}');
});

setTimeout(() => {
  const http = require('http');
  const data = JSON.stringify({ email: 'colinnebula@gmail.com' });
  const options = {
    hostname: 'localhost',
    port: 8082,
    path: '/test',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': data.length
    }
  };
  
  const req = http.request(options, res => {
    let body = '';
    res.on('data', chunk => { body += chunk; });
    res.on('end', () => {
      console.log('\nResponse:', body);
    });
  });
  
  req.write(data);
  req.end();
}, 1000);
