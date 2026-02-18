const fs = require('fs');
const path = require('path');

// Create a simple 1024x1024 PNG icon programmatically
// This creates a shield icon with a checkmark

const { createCanvas } = require('canvas');

const size = 1024;
const canvas = createCanvas(size, size);
const ctx = canvas.getContext('2d');

// Background with gradient
const gradient = ctx.createLinearGradient(0, 0, size, size);
gradient.addColorStop(0, '#667eea');
gradient.addColorStop(1, '#764ba2');

// Draw circle background
ctx.beginPath();
ctx.arc(size / 2, size / 2, 480, 0, 2 * Math.PI);
ctx.fillStyle = gradient;
ctx.fill();

// Draw shield shape
ctx.beginPath();
ctx.moveTo(size / 2, 160);
ctx.lineTo(760, 280);
ctx.lineTo(760, 520);
ctx.quadraticCurveTo(760, 680, size / 2, 840);
ctx.quadraticCurveTo(264, 680, 264, 520);
ctx.lineTo(264, 280);
ctx.closePath();
ctx.fillStyle = 'rgba(255, 255, 255, 0.95)';
ctx.fill();

// Draw inner shield
ctx.beginPath();
ctx.moveTo(size / 2, 220);
ctx.lineTo(720, 320);
ctx.lineTo(720, 520);
ctx.quadraticCurveTo(720, 650, size / 2, 780);
ctx.quadraticCurveTo(304, 650, 304, 520);
ctx.lineTo(304, 320);
ctx.closePath();
ctx.fillStyle = gradient;
ctx.fill();

// Draw checkmark
ctx.strokeStyle = 'white';
ctx.lineWidth = 40;
ctx.lineCap = 'round';
ctx.lineJoin = 'round';
ctx.beginPath();
ctx.moveTo(440, 500);
ctx.lineTo(490, 560);
ctx.lineTo(610, 420);
ctx.stroke();

// Draw glow on checkmark
ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
ctx.lineWidth = 52;
ctx.globalAlpha = 0.4;
ctx.beginPath();
ctx.moveTo(440, 500);
ctx.lineTo(490, 560);
ctx.lineTo(610, 420);
ctx.stroke();
ctx.globalAlpha = 1;

// Add sparkles
ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
ctx.beginPath();
ctx.arc(400, 360, 8, 0, 2 * Math.PI);
ctx.fill();
ctx.beginPath();
ctx.arc(624, 360, 8, 0, 2 * Math.PI);
ctx.fill();
ctx.beginPath();
ctx.arc(size / 2, 640, 8, 0, 2 * Math.PI);
ctx.fill();

// Save as PNG
const buffer = canvas.toBuffer('image/png');
fs.writeFileSync(path.join(__dirname, 'icon.png'), buffer);
console.log('✅ Icon generated: build-resources/icon.png');
console.log('Now generating platform-specific icons...');
