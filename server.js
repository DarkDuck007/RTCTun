const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const wrtc = require("wrtc");

const PORT = process.env.PORT || 8080;
const INDEX_PATH = path.join(__dirname, "index.html");

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    fs.readFile(INDEX_PATH, (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Failed to load index.html");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(data);
    });
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

const wss = new WebSocket.Server({ server });
let nextClientId = 1;
const clients = new Map();

wss.on("connection", (ws) => {
  let pc;
  let channel;
  const clientId = nextClientId++;

  clients.set(ws, { id: clientId, pc: null, channel: null });

  function broadcastFrom(senderId, text) {
    for (const client of clients.values()) {
      if (!client.channel || client.id === senderId) continue;
      if (client.channel.readyState !== "open") continue;
      client.channel.send(`Client ${senderId}: ${text}`);
    }
  }

  ws.on("message", async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (err) {
      console.warn("Invalid JSON message");
      return;
    }

    if (msg.type === "offer") {
      pc = new wrtc.RTCPeerConnection({
        iceServers: msg.iceServers || [],
      });
      clients.get(ws).pc = pc;

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          ws.send(
            JSON.stringify({
              type: "candidate",
              candidate: event.candidate,
            })
          );
        }
      };

      pc.ondatachannel = (event) => {
        channel = event.channel;
        clients.get(ws).channel = channel;
        channel.onmessage = (ev) => {
          console.log(`Client ${clientId} message:`, ev.data);
          broadcastFrom(clientId, ev.data);
        };
        channel.onopen = () => {
          console.log(`Data channel open for client ${clientId}`);
          channel.send(`Connected as Client ${clientId}.`);
        };
        channel.onclose = () => {
          console.log(`Data channel closed for client ${clientId}`);
        };
      };

      try {
        await pc.setRemoteDescription(msg.sdp);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(
          JSON.stringify({
            type: "answer",
            sdp: pc.localDescription,
          })
        );
      } catch (err) {
        console.error("Failed to handle offer:", err);
      }
      return;
    }

    if (msg.type === "candidate" && pc) {
      try {
        await pc.addIceCandidate(msg.candidate);
      } catch (err) {
        console.error("Failed to add ICE candidate:", err);
      }
      return;
    }
  });

  ws.on("close", () => {
    if (channel && channel.readyState === "open") {
      channel.close();
    }
    if (pc) {
      pc.close();
      pc = null;
    }
    clients.delete(ws);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on http://0.0.0.0:${PORT}`);
});
