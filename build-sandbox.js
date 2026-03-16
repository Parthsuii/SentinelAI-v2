const fs = require('fs');
const html = '<!DOCTYPE html>\n<html>\n<head><title>SentinelAI Sandbox</title></head>\n<body>\n<script src="sandbox-frame.js"></script>\n</body>\n</html>\n';
fs.writeFileSync('content/sandbox-frame.html', html);

let manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));

manifest.content_security_policy.sandbox = "sandbox allow-scripts; script-src 'self'; child-src 'self';";

fs.writeFileSync('manifest.json', JSON.stringify(manifest, null, 2));
console.log('Successfully updated manifest.json and content/sandbox-frame.html');
