package com.rtctun.client

import android.app.Application

class RTCTunApp : Application() {
    override fun onCreate() {
        super.onCreate()
        WebRtc.initialize(applicationContext)
    }
}
