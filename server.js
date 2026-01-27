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

wss.on("connection", (ws) => {
  let pc;

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
        const channel = event.channel;
        channel.onmessage = (ev) => {
          console.log("Client message:", ev.data);
        };
        channel.onopen = () => {
          console.log("Data channel open");
        };
        channel.onclose = () => {
          console.log("Data channel closed");
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
    if (pc) {
      pc.close();
      pc = null;
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
