const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const file = path.join(__dirname, "..", "internal", "broker", "adminui", "index.html");
const html = fs.readFileSync(file, "utf8");
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1].trim())
  .filter(Boolean);

if (scripts.length !== 1) {
  throw new Error(`Expected one inline administration script, found ${scripts.length}`);
}

new vm.Script(scripts[0], { filename: "internal/broker/adminui/index.html" });
console.log("Administration UI JavaScript syntax is valid.");
