const net = require("net");
const WebSocket = require("ws");
const wrtc = require("wrtc");

const SERVER_URL = process.env.SERVER_URL || "ws://localhost:8080";
const STUN_URL = process.env.STUN_URL || "stun:stun3.l.google.com:5349";
const SOCKS_HOST = process.env.SOCKS_HOST || "127.0.0.1";
const SOCKS_PORT = Number(process.env.SOCKS_PORT || 1080);

let ws;
let pc;
let channel;
let nextConnId = 1;
const socksConnections = new Map();

function log(message) {
  console.log(`[socks-client] ${message}`);
}

function sendSocksMessage(payload) {
  if (!channel || channel.readyState !== "open") return false;
  channel.send(JSON.stringify({ type: "socks", ...payload }));
  return true;
}

function parseSocksRequest(buffer) {
  if (buffer.length < 4) return null;
  const ver = buffer[0];
  const cmd = buffer[1];
  const rsv = buffer[2];
  const atyp = buffer[3];
  if (ver !== 0x05 || rsv !== 0x00) {
    return { error: "Invalid SOCKS version" };
  }
  if (cmd !== 0x01) {
    return { error: "Only CONNECT is supported" };
  }
  let offset = 4;
  let host;
  if (atyp === 0x01) {
    if (buffer.length < offset + 4 + 2) return null;
    host = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
    offset += 4;
  } else if (atyp === 0x03) {
    if (buffer.length < offset + 1) return null;
    const len = buffer[offset];
    offset += 1;
    if (buffer.length < offset + len + 2) return null;
    host = buffer.slice(offset, offset + len).toString("utf8");
    offset += len;
  } else if (atyp === 0x04) {
    if (buffer.length < offset + 16 + 2) return null;
    const addr = buffer.slice(offset, offset + 16);
    host = addr.toString("hex").match(/.{1,4}/g).join(":");
    offset += 16;
  } else {
    return { error: "Unsupported address type" };
  }

  const port = buffer.readUInt16BE(offset);
  offset += 2;
  return { host, port, bytesUsed: offset };
}

function buildReply(rep) {
  const reply = Buffer.alloc(10);
  reply[0] = 0x05;
  reply[1] = rep;
  reply[2] = 0x00;
  reply[3] = 0x01;
  reply.writeUInt32BE(0, 4);
  reply.writeUInt16BE(0, 8);
  return reply;
}

function handleSocksConnection(socket) {
  socket.setNoDelay(true);
  socket.pause();

  const connId = nextConnId++;
  const state = {
    id: connId,
    stage: "greeting",
    buffer: Buffer.alloc(0),
    pending: [],
    opened: false,
    socket,
  };

  socksConnections.set(connId, state);

  function failAndClose(reason) {
    log(`SOCKS ${connId} error: ${reason}`);
    try {
      socket.write(buildReply(0x01));
    } catch (_) {
      // ignore
    }
    socket.destroy();
    socksConnections.delete(connId);
  }

  socket.on("data", (chunk) => {
    if (state.opened) {
      sendSocksMessage({ action: "data", id: connId, data: chunk.toString("base64") });
      return;
    }
    state.buffer = Buffer.concat([state.buffer, chunk]);

    while (true) {
      if (state.stage === "greeting") {
        if (state.buffer.length < 2) return;
        const ver = state.buffer[0];
        const nmethods = state.buffer[1];
        if (ver !== 0x05) {
          failAndClose("Invalid greeting");
          return;
        }
        if (state.buffer.length < 2 + nmethods) return;
        state.buffer = state.buffer.slice(2 + nmethods);
        socket.write(Buffer.from([0x05, 0x00]));
        state.stage = "request";
        continue;
      }

      if (state.stage === "request") {
        const req = parseSocksRequest(state.buffer);
        if (!req) return;
        if (req.error) {
          failAndClose(req.error);
          return;
        }

        state.buffer = state.buffer.slice(req.bytesUsed);
        state.stage = "open";
        state.pending.push(state.buffer);
        state.buffer = Buffer.alloc(0);

        if (!sendSocksMessage({ action: "open", id: connId, host: req.host, port: req.port })) {
          failAndClose("Data channel not open");
          return;
        }

        socket.pause();
        return;
      }

      return;
    }
  });

  socket.on("close", () => {
    sendSocksMessage({ action: "close", id: connId });
    socksConnections.delete(connId);
  });

  socket.on("error", (err) => {
    log(`SOCKS ${connId} socket error: ${err.message}`);
    sendSocksMessage({ action: "close", id: connId });
    socksConnections.delete(connId);
  });
}

function handleServerMessage(message) {
  let payload;
  try {
    payload = JSON.parse(message);
  } catch (err) {
    return;
  }
  if (payload.type !== "socks") return;

  const state = socksConnections.get(payload.id);
  if (!state) return;

  if (payload.action === "opened") {
    state.opened = true;
    state.socket.write(buildReply(0x00));
    for (const chunk of state.pending) {
      if (chunk.length) {
        sendSocksMessage({ action: "data", id: state.id, data: chunk.toString("base64") });
      }
    }
    state.pending = [];
    state.socket.resume();
    return;
  }

  if (payload.action === "data") {
    const data = Buffer.from(payload.data || "", "base64");
    state.socket.write(data);
    return;
  }

  if (payload.action === "error") {
    state.socket.write(buildReply(0x01));
    state.socket.destroy();
    socksConnections.delete(state.id);
    return;
  }

  if (payload.action === "close") {
    state.socket.end();
    socksConnections.delete(state.id);
  }
}

async function start() {
  ws = new WebSocket(SERVER_URL);

  ws.on("open", async () => {
    log(`WebSocket connected to ${SERVER_URL}`);
    pc = new wrtc.RTCPeerConnection({
      iceServers: [{ urls: STUN_URL }],
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

    pc.onconnectionstatechange = () => {
      log(`Peer connection: ${pc.connectionState}`);
    };

    channel = pc.createDataChannel("rtctun-socks");
    channel.onopen = () => log("Data channel open");
    channel.onclose = () => log("Data channel closed");
    channel.onmessage = (event) => {
      const text = event.data.toString();
      handleServerMessage(text);
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    ws.send(
      JSON.stringify({
        type: "offer",
        sdp: pc.localDescription,
        iceServers: [{ urls: STUN_URL }],
      })
    );
  });

  ws.on("message", async (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (err) {
      return;
    }
    if (msg.type === "answer") {
      await pc.setRemoteDescription(msg.sdp);
      log("Received answer from server");
    } else if (msg.type === "candidate") {
      await pc.addIceCandidate(msg.candidate);
    }
  });

  ws.on("close", () => {
    log("WebSocket closed");
  });

  ws.on("error", (err) => {
    log(`WebSocket error: ${err.message}`);
  });
}

const socksServer = net.createServer(handleSocksConnection);

socksServer.listen(SOCKS_PORT, SOCKS_HOST, () => {
  log(`SOCKS5 proxy listening on ${SOCKS_HOST}:${SOCKS_PORT}`);
  start().catch((err) => log(`Failed to start: ${err.message}`));
});
