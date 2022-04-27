package com.jhomlala.better_player.drm

import android.net.Uri
import com.google.android.exoplayer2.C
import com.google.android.exoplayer2.MediaItem
import com.google.android.exoplayer2.drm.*
import com.google.android.exoplayer2.upstream.HttpDataSource
import com.google.android.exoplayer2.util.Assertions
import com.google.common.primitives.Ints

class CustomDrmSessionManagerProvider(
    private var lock: Any? = Any(),
    private var manager: DrmSessionManager? = null,
    private var drmHttpDataSourceFactory: HttpDataSource.Factory,
    private var drmLicenseUrl: String
): DrmSessionManagerProvider {

    override operator fun get(mediaItem: MediaItem): DrmSessionManager {
        synchronized(lock!!) {
            manager = createManager()
            return Assertions.checkNotNull(manager)
        }
    }

    private fun createManager(): DrmSessionManager {

        val httpDrmCallback = HttpMediaDrmCallback(
            if (Uri.parse(drmLicenseUrl) == null) null else Uri.parse(drmLicenseUrl).toString(),
            false,
            drmHttpDataSourceFactory
        )

        val httpRequestHeaders: HashMap<String, String> = HashMap()
        for ((key, value) in httpRequestHeaders) {
            httpDrmCallback.setKeyRequestProperty(key, value)
        }

        val drmSessionManager = DefaultDrmSessionManager.Builder()
            .setUuidAndExoMediaDrmProvider(
                C.WIDEVINE_UUID, FrameworkMediaDrm.DEFAULT_PROVIDER
            )
            .setMultiSession(true)
            .setPlayClearSamplesWithoutKeys(true)
            .setUseDrmSessionsForClearContent(*Ints.toArray(emptyList()))
            .build(httpDrmCallback)
        drmSessionManager.setMode(DefaultDrmSessionManager.MODE_PLAYBACK, null)
        return drmSessionManager
    }

}