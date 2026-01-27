const http = require("http");
const fs = require("fs");
const path = require("path");
const net = require("net");
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
  const socksConnections = new Map();
  const clientId = nextClientId++;

  clients.set(ws, { id: clientId, pc: null, channel: null });

  function broadcastFrom(senderId, text) {
    for (const client of clients.values()) {
      if (!client.channel || client.id === senderId) continue;
      if (client.channel.readyState !== "open") continue;
      client.channel.send(`Client ${senderId}: ${text}`);
    }
  }

  function sendSocksMessage(payload) {
    if (!channel || channel.readyState !== "open") return;
    channel.send(JSON.stringify({ type: "socks", ...payload }));
  }

  function closeSocksConnection(id) {
    const socket = socksConnections.get(id);
    if (!socket) return;
    socksConnections.delete(id);
    socket.destroy();
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
          const raw = ev.data.toString();
          let payload;
          try {
            payload = JSON.parse(raw);
          } catch (err) {
            console.log(`Client ${clientId} message:`, raw);
            broadcastFrom(clientId, raw);
            return;
          }

          if (payload.type !== "socks") {
            console.log(`Client ${clientId} message:`, raw);
            broadcastFrom(clientId, raw);
            return;
          }

          if (payload.action === "open") {
            const { id, host, port } = payload;
            if (!id || !host || !port) {
              sendSocksMessage({ action: "error", id, message: "Invalid open request" });
              return;
            }
            if (socksConnections.has(id)) {
              sendSocksMessage({ action: "error", id, message: "Connection already exists" });
              return;
            }

            const socket = net.connect({ host, port: Number(port) }, () => {
              sendSocksMessage({ action: "opened", id });
            });

            socksConnections.set(id, socket);

            socket.on("data", (chunk) => {
              sendSocksMessage({ action: "data", id, data: chunk.toString("base64") });
            });

            socket.on("error", (err) => {
              sendSocksMessage({ action: "error", id, message: err.message });
              closeSocksConnection(id);
            });

            socket.on("close", () => {
              sendSocksMessage({ action: "close", id });
              closeSocksConnection(id);
            });

            return;
          }

          if (payload.action === "data") {
            const { id, data } = payload;
            const socket = socksConnections.get(id);
            if (!socket) return;
            if (!data) return;
            socket.write(Buffer.from(data, "base64"));
            return;
          }

          if (payload.action === "close") {
            closeSocksConnection(payload.id);
            return;
          }
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
    for (const id of socksConnections.keys()) {
      closeSocksConnection(id);
    }
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
