/**
 * SentinelAI v2.0 — Icon Generator
 * Generates PNG icons at 16, 48, and 128px using Canvas API.
 * Run: node scripts/generate-icons.js
 */

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

const sizes = [16, 48, 128];
const outDir = path.join(__dirname, '..', 'icons');

if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

sizes.forEach(size => {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const cx = size / 2;
  const cy = size / 2;
  const r = size * 0.42;

  // Background circle
  const bgGrad = ctx.createLinearGradient(0, 0, size, size);
  bgGrad.addColorStop(0, '#0a0e1a');
  bgGrad.addColorStop(1, '#111827');
  ctx.beginPath();
  ctx.arc(cx, cy, size / 2, 0, Math.PI * 2);
  ctx.fillStyle = bgGrad;
  ctx.fill();

  // Shield outline
  const grad = ctx.createLinearGradient(0, 0, size, size);
  grad.addColorStop(0, '#00e5ff');
  grad.addColorStop(1, '#7c4dff');

  ctx.strokeStyle = grad;
  ctx.lineWidth = Math.max(1.5, size * 0.06);
  ctx.beginPath();
  ctx.moveTo(cx, cy - r);
  ctx.lineTo(cx - r * 0.85, cy - r * 0.5);
  ctx.lineTo(cx - r * 0.85, cy + r * 0.2);
  ctx.quadraticCurveTo(cx, cy + r, cx, cy + r);
  ctx.quadraticCurveTo(cx, cy + r, cx + r * 0.85, cy + r * 0.2);
  ctx.lineTo(cx + r * 0.85, cy - r * 0.5);
  ctx.closePath();
  ctx.stroke();

  // Center dot
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.2, 0, Math.PI * 2);
  ctx.fill();

  // Save
  const buf = canvas.toBuffer('image/png');
  const filePath = path.join(outDir, `icon-${size}.png`);
  fs.writeFileSync(filePath, buf);
  console.log(`Generated: ${filePath}`);
});

console.log('Done! Icons generated in icons/');
