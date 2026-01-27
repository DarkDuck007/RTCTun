package com.rtctun.client

import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import java.net.InetSocketAddress
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class MainActivity : AppCompatActivity() {
    private lateinit var serverUrlInput: EditText
    private lateinit var stunUrlInput: EditText
    private lateinit var socksPortInput: EditText
    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var connectButton: Button

    private val executor = Executors.newCachedThreadPool()
    private val uiExecutor = Executors.newSingleThreadExecutor()
    private val socksConnections = ConcurrentHashMap<Long, SocksConnection>()
    private val nextConnId = AtomicLong(1)

    private var ws: WebSocket? = null
    private var pc: PeerConnection? = null
    private var channel: DataChannel? = null
    private var serverSocket: ServerSocket? = null
    private var pendingSocksPort: Int = -1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        serverUrlInput = findViewById(R.id.serverUrl)
        stunUrlInput = findViewById(R.id.stunUrl)
        socksPortInput = findViewById(R.id.socksPort)
        statusText = findViewById(R.id.status)
        logText = findViewById(R.id.log)
        connectButton = findViewById(R.id.connectButton)

        serverUrlInput.setText("wss://idoabsolutelynothing.topolly84.workers.dev:443")
        stunUrlInput.setText("stun:stun3.l.google.com:5349")
        socksPortInput.setText("6075")

        connectButton.setOnClickListener {
            if (ws == null) {
                startClient()
            } else {
                stopClient()
            }
        }

    }

    override fun onDestroy() {
        super.onDestroy()
        stopClient()
        executor.shutdownNow()
        uiExecutor.shutdownNow()
    }

    private fun startClient() {
        val serverUrl = serverUrlInput.text.toString().trim()
        val stunUrl = stunUrlInput.text.toString().trim()
        val socksPort = socksPortInput.text.toString().toIntOrNull() ?: 1080

        setStatus("Connecting...")
        pendingSocksPort = socksPort

        val client = OkHttpClient()
        val request = Request.Builder().url(serverUrl).build()
        ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                log("WebSocket connected")
                createPeerConnection(stunUrl, webSocket)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleSignalMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                log("WebSocket error: ${t.message}")
                setStatus("WebSocket error")
                stopClient()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                log("WebSocket closed: $reason")
                setStatus("Disconnected")
                stopClient()
            }
        })

        setStatus("Connecting WebSocket...")
        connectButton.text = "Disconnect"
    }

    private fun stopClient() {
        channel?.close()
        channel = null
        pc?.close()
        pc = null
        ws?.close(1000, "Client closed")
        ws = null
        serverSocket?.close()
        serverSocket = null
        pendingSocksPort = -1
        socksConnections.values.forEach { it.close() }
        socksConnections.clear()
        setStatus("Idle")
        connectButton.text = "Connect"
    }

    private fun createPeerConnection(stunUrl: String, webSocket: WebSocket) {
        val factory = WebRtc.getFactory(applicationContext)
        val iceServers = listOf(PeerConnection.IceServer.builder(stunUrl).createIceServer())

        pc = factory.createPeerConnection(iceServers, object : PeerConnection.Observer {
            override fun onIceCandidate(candidate: IceCandidate) {
                val msg = JSONObject()
                msg.put("type", "candidate")
                msg.put("candidate", JSONObject()
                    .put("candidate", candidate.sdp)
                    .put("sdpMid", candidate.sdpMid)
                    .put("sdpMLineIndex", candidate.sdpMLineIndex))
                webSocket.send(msg.toString())
            }

            override fun onDataChannel(dc: DataChannel) {
                channel = dc
                setupDataChannel()
            }

            override fun onConnectionChange(newState: PeerConnection.PeerConnectionState) {
                setStatus("Peer connection: $newState")
            }

            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
            override fun onSignalingChange(state: PeerConnection.SignalingState) {}
            override fun onIceConnectionReceivingChange(receiving: Boolean) {}
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {}
            override fun onIceCandidatesRemoved(candidates: Array<IceCandidate>) {}
            override fun onAddStream(stream: org.webrtc.MediaStream) {}
            override fun onRemoveStream(stream: org.webrtc.MediaStream) {}
            override fun onRenegotiationNeeded() {}
            override fun onAddTrack(receiver: RtpReceiver, streams: Array<out org.webrtc.MediaStream>) {}
        })

        channel = pc?.createDataChannel("rtctun-socks", DataChannel.Init())
        setupDataChannel()

        pc?.createOffer(object : SimpleSdpObserver() {
            override fun onCreateSuccess(desc: SessionDescription) {
                pc?.setLocalDescription(SimpleSdpObserver(), desc)
                val msg = JSONObject()
                msg.put("type", "offer")
                msg.put("sdp", JSONObject().put("type", desc.type.canonicalForm()).put("sdp", desc.description))
                msg.put("iceServers", org.json.JSONArray().put(JSONObject().put("urls", stunUrl)))
                webSocket.send(msg.toString())
            }
        }, MediaConstraints())
    }

    private fun setupDataChannel() {
        channel?.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(previousAmount: Long) {}
            override fun onStateChange() {
                log("Data channel state: ${channel?.state()}")
                if (channel?.state() == DataChannel.State.OPEN && serverSocket == null) {
                    val port = if (pendingSocksPort > 0) pendingSocksPort else 1080
                    log("Starting SOCKS5 on 127.0.0.1:$port")
                    startSocksServer(port)
                }
            }

            override fun onMessage(buffer: DataChannel.Buffer) {
                val data = ByteArray(buffer.data.remaining())
                buffer.data.get(data)
                handleTunnelMessage(String(data, Charsets.UTF_8))
            }
        })
    }

    private fun handleSignalMessage(text: String) {
        val msg = JSONObject(text)
        when (msg.getString("type")) {
            "answer" -> {
                val sdp = msg.getJSONObject("sdp")
                val desc = SessionDescription(SessionDescription.Type.ANSWER, sdp.getString("sdp"))
                pc?.setRemoteDescription(SimpleSdpObserver(), desc)
                log("Received answer")
            }
            "candidate" -> {
                val cand = msg.getJSONObject("candidate")
                val candidate = IceCandidate(
                    cand.getString("sdpMid"),
                    cand.getInt("sdpMLineIndex"),
                    cand.getString("candidate")
                )
                pc?.addIceCandidate(candidate)
            }
        }
    }

    private fun handleTunnelMessage(text: String) {
        val msg = try {
            JSONObject(text)
        } catch (err: Exception) {
            return
        }
        if (msg.optString("type") != "socks") return
        val id = msg.optLong("id")
        val conn = socksConnections[id] ?: return

        when (msg.optString("action")) {
            "opened" -> conn.onOpened()
            "data" -> {
                val data = msg.optString("data", "")
                if (data.isNotEmpty()) {
                    conn.write(Base64.decode(data, Base64.NO_WRAP))
                }
            }
            "error" -> {
                conn.fail()
                socksConnections.remove(id)
            }
            "close" -> {
                conn.close()
                socksConnections.remove(id)
            }
        }
    }

    private fun sendTunnelMessage(payload: JSONObject) {
        val dc = channel ?: return
        if (dc.state() != DataChannel.State.OPEN) return
        val data = payload.toString().toByteArray(Charsets.UTF_8)
        dc.send(DataChannel.Buffer(java.nio.ByteBuffer.wrap(data), false))
    }

    private fun startSocksServer(port: Int) {
        serverSocket = ServerSocket()
        serverSocket?.bind(InetSocketAddress("127.0.0.1", port))
        executor.execute {
            try {
                while (!serverSocket!!.isClosed) {
                    val client = serverSocket!!.accept()
                    handleSocksClient(client)
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun handleSocksClient(socket: Socket) {
        executor.execute {
            val connId = nextConnId.getAndIncrement()
            val conn = SocksConnection(connId, socket)
            socksConnections[connId] = conn

            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                fun readExactly(len: Int): ByteArray {
                    val buf = ByteArray(len)
                    var offset = 0
                    while (offset < len) {
                        val read = input.read(buf, offset, len - offset)
                        if (read == -1) throw IllegalStateException("Unexpected EOF")
                        offset += read
                    }
                    return buf
                }

                val ver = input.read()
                val nmethods = input.read()
                if (ver != 0x05 || nmethods < 0) {
                    socket.close()
                    return@execute
                }
                if (nmethods > 0) {
                    readExactly(nmethods)
                }
                output.write(byteArrayOf(0x05, 0x00))

                val req = readExactly(4)
                if (req[1].toInt() != 0x01) {
                    output.write(buildReply(0x07))
                    socket.close()
                    return@execute
                }

                val host = when (req[3].toInt() and 0xFF) {
                    0x01 -> {
                        val addr = readExactly(4)
                        "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}.${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
                    }
                    0x03 -> {
                        val len = input.read()
                        val addr = readExactly(len)
                        String(addr)
                    }
                    0x04 -> {
                        val addr = readExactly(16)
                        InetAddress.getByAddress(addr).hostAddress ?: run {
                            output.write(buildReply(0x08))
                            socket.close()
                            return@execute
                        }
                    }
                    else -> {
                        output.write(buildReply(0x08))
                        socket.close()
                        return@execute
                    }
                }
                val portBytes = readExactly(2)
                val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

                conn.setOutput(output)
                sendTunnelMessage(JSONObject()
                    .put("type", "socks")
                    .put("action", "open")
                    .put("id", connId)
                    .put("host", host)
                    .put("port", port))

                if (!conn.awaitOpened()) {
                    output.write(buildReply(0x01))
                    socket.close()
                    socksConnections.remove(connId)
                    return@execute
                }

                output.write(buildReply(0x00))
                conn.startRelay(this::sendTunnelMessage)
            } catch (err: Exception) {
                conn.close()
                socksConnections.remove(connId)
            }
        }
    }

    private fun buildReply(rep: Int): ByteArray {
        return byteArrayOf(0x05, rep.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)
    }

    private fun setStatus(message: String) {
        runOnUiThread { statusText.text = message }
    }

    private fun log(message: String) {
        runOnUiThread {
            logText.text = "$message\n${logText.text}"
        }
    }

    private open class SimpleSdpObserver : SdpObserver {
        override fun onCreateSuccess(desc: SessionDescription) {}
        override fun onSetSuccess() {}
        override fun onCreateFailure(error: String) {}
        override fun onSetFailure(error: String) {}
    }

    private class SocksConnection(private val id: Long, private val socket: Socket) {
        private val lock = Object()
        private var opened = false
        private var output: java.io.OutputStream? = null

        fun setOutput(out: java.io.OutputStream) {
            output = out
        }

        fun awaitOpened(timeoutMs: Long = 10000): Boolean {
            val start = System.currentTimeMillis()
            synchronized(lock) {
                while (!opened && System.currentTimeMillis() - start < timeoutMs) {
                    lock.wait(200)
                }
                return opened
            }
        }

        fun onOpened() {
            synchronized(lock) {
                opened = true
                lock.notifyAll()
            }
        }

        fun write(bytes: ByteArray) {
            output?.write(bytes)
            output?.flush()
        }

        fun fail() {
            close()
        }

        fun close() {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }

        fun startRelay(send: (JSONObject) -> Unit) {
            val input = socket.getInputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count == -1) {
                    send(JSONObject().put("type", "socks").put("action", "close").put("id", id))
                    break
                }
                val data = Base64.encodeToString(buffer.copyOf(count), Base64.NO_WRAP)
                send(JSONObject().put("type", "socks").put("action", "data").put("id", id).put("data", data))
            }
        }
    }
}
