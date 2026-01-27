package com.rtctun.client

import android.content.Context
import org.webrtc.Logging
import org.webrtc.PeerConnectionFactory

object WebRtc {
    @Volatile
    private var initialized = false
    private var factory: PeerConnectionFactory? = null

    fun initialize(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context)
                    .setNativeLibraryName("jingle_peerconnection_so")
                    .createInitializationOptions()
            )
            Logging.enableLogToDebugOutput(Logging.Severity.LS_INFO)
            factory = PeerConnectionFactory.builder().createPeerConnectionFactory()
            initialized = true
        }
    }

    fun getFactory(context: Context): PeerConnectionFactory {
        if (!initialized) {
            initialize(context.applicationContext)
        }
        return factory ?: throw IllegalStateException("WebRTC factory not initialized")
    }
}
