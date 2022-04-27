package com.jhomlala.better_player.drm

import android.net.Uri
import android.util.ArrayMap
import com.google.android.exoplayer2.C
import com.google.android.exoplayer2.upstream.*
import com.google.android.exoplayer2.upstream.HttpDataSource.*
import com.google.android.exoplayer2.util.Assertions
import com.google.android.exoplayer2.util.Log
import com.google.android.exoplayer2.util.Util
import com.google.common.base.Predicate
import com.google.common.net.HttpHeaders
import org.json.JSONException
import org.json.JSONObject
import java.io.*
import java.net.HttpURLConnection
import java.net.NoRouteToHostException
import java.net.ProtocolException
import java.net.URL
import java.util.*
import java.util.zip.GZIPInputStream

open class CustomDrmHttpDataSource private constructor(
    private val userAgent: String?,
    private val token: String?,
    private val sessionToken: String?,
    private val connectTimeoutMillis: Int,
    private val readTimeoutMillis: Int,
    private val allowCrossProtocolRedirects: Boolean,
    private val defaultRequestProperties: RequestProperties?,
    private val contentTypePredicate: Predicate<String>?
) : BaseDataSource(true), HttpDataSource {

    class Factory : HttpDataSource.Factory {

        private val defaultRequestProperties: RequestProperties = RequestProperties()
        private var transferListener: TransferListener? = null
        private var contentTypePredicate: Predicate<String>? = null
        private var userAgent: String? = null
        private var connectTimeoutMs: Int
        private var readTimeoutMs: Int
        private var allowCrossProtocolRedirects = false
        private var token: String? = null
        private var sessionToken: String? = null

        init {
            connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MILLIS
            readTimeoutMs = DEFAULT_READ_TIMEOUT_MILLIS
        }

        fun setAuthToken(token: String?): Factory {
            this.token = token
            return this
        }

        fun setSessionToken(sessionToken: String?): Factory {
            this.sessionToken = sessionToken
            return this
        }

        override fun setDefaultRequestProperties(defaultRequestProperties: Map<String, String>): Factory {
            this.defaultRequestProperties.clearAndSet(defaultRequestProperties)
            return this
        }

        fun setUserAgent(userAgent: String?): Factory {
            this.userAgent = userAgent
            return this
        }

        fun setTransferListener(transferListener: TransferListener?): Factory {
            this.transferListener = transferListener
            return this
        }

        override fun createDataSource(): CustomDrmHttpDataSource {
            val dataSource = CustomDrmHttpDataSource(
                userAgent,
                token,
                sessionToken,
                connectTimeoutMs,
                readTimeoutMs,
                allowCrossProtocolRedirects,
                defaultRequestProperties,
                contentTypePredicate
            )
            if (transferListener != null) {
                dataSource.addTransferListener(transferListener!!)
            }
            return dataSource
        }
    }

    companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 8 * 1000
        const val DEFAULT_READ_TIMEOUT_MILLIS = 8 * 1000
        private const val TAG = "CustomDrmHttpDataSource"
        private const val MAX_REDIRECTS = 20 // Same limit as okhttp.
        private const val HTTP_STATUS_TEMPORARY_REDIRECT = 307
        private const val HTTP_STATUS_PERMANENT_REDIRECT = 308
        private const val MAX_BYTES_TO_DRAIN: Long = 2048
    }

    private val requestProperties: RequestProperties = RequestProperties()
    private var dataSpec: DataSpec? = null
    private var connection: HttpURLConnection? = null
    private var inputStream: InputStream? = null
    private var opened = false
    private var responseCode = 0
    private var bytesToRead: Long = 0
    private var bytesRead: Long = 0

    override fun getUri(): Uri? {
        return if (connection == null) null else Uri.parse(connection!!.url.toString())
    }

    override fun getResponseCode(): Int {
        return if (connection == null || responseCode <= 0) -1 else responseCode
    }

    override fun getResponseHeaders(): Map<String, List<String>> {
        return if (connection == null) emptyMap() else connection!!.headerFields
    }

    override fun setRequestProperty(name: String, value: String) {
        Assertions.checkNotNull(name)
        Assertions.checkNotNull(value)
        requestProperties[name] = value
    }

    override fun clearRequestProperty(name: String) {
        Assertions.checkNotNull(name)
        requestProperties.remove(name)
    }

    override fun clearAllRequestProperties() {
        requestProperties.clear()
    }

    override fun open(originalDataSpec: DataSpec): Long {

        var query: JSONObject? = null
        val httpRequestHeaders: MutableMap<String, String> = ArrayMap()

        if("https://hermes.brasilparalelo.com.br/api" == originalDataSpec.uri.toString()) {
            val challenge = android.util.Base64.encodeToString(originalDataSpec.httpBody, android.util.Base64.NO_WRAP)
            query = JSONObject()
            try {
                query.accumulate(
                    "query", "{drm_license(" +
                            "session_token: \"$sessionToken\", " +
                            "license_challenge: \"$challenge\"" +
                            ") { ...on license { license } ...on error {message}}}"
                )
            } catch (e: JSONException) {
                e.printStackTrace()
            }
            httpRequestHeaders["content-type"] = "application/json"
            httpRequestHeaders["Authorization"] = "Bearer $token"
        }

        this.dataSpec = DataSpec.Builder()
            .setUri(originalDataSpec.uri)
            .setHttpRequestHeaders(if (httpRequestHeaders.isEmpty()) originalDataSpec.httpRequestHeaders else httpRequestHeaders)
            .setHttpMethod(DataSpec.HTTP_METHOD_POST)
            .setHttpBody(originalDataSpec.httpBody)
            .setFlags(DataSpec.FLAG_ALLOW_GZIP)
            .build()
        bytesRead = 0
        bytesToRead = 0
        transferInitializing(dataSpec!!)
        connection = try {
            makeConnection(dataSpec!!, query)
        } catch (e: IOException) {
            val message = e.message
            if (message != null && message.contains("cleartext http traffic.*not permitted.*")) {
                throw CleartextNotPermittedException(e, dataSpec!!)
            }
            throw HttpDataSourceException("Unable to connect", e, dataSpec!!, HttpDataSourceException.TYPE_OPEN)
        }
        val connection = connection
        val responseMessage: String
        try {
            responseCode = connection!!.responseCode
            responseMessage = connection.responseMessage
        } catch (e: IOException) {
            closeConnectionQuietly()
            throw HttpDataSourceException("Unable to connect", e, dataSpec!!, HttpDataSourceException.TYPE_OPEN)
        }

        if (responseCode < 200 || responseCode > 299) {
            val headers = connection.headerFields
            if (responseCode == 416) {
                val documentSize =
                    HttpUtil.getDocumentSize(connection.getHeaderField(HttpHeaders.CONTENT_RANGE))
                if (dataSpec!!.position == documentSize) {
                    opened = true
                    transferStarted(dataSpec!!)
                    return if (dataSpec!!.length != C.LENGTH_UNSET.toLong()) dataSpec!!.length else 0
                }
            }
            val errorStream = connection.errorStream
            val errorResponseBody: ByteArray = try {
                if (errorStream != null) Util.toByteArray(errorStream) else Util.EMPTY_BYTE_ARRAY
            } catch (e: IOException) {
                Util.EMPTY_BYTE_ARRAY
            }
            closeConnectionQuietly()
            val exception = InvalidResponseCodeException(
                responseCode, responseMessage, null, headers, dataSpec!!, errorResponseBody
            )
            if (responseCode == 416) {
                exception.initCause(DataSourceException(DataSourceException.POSITION_OUT_OF_RANGE))
            }
            throw exception
        }

        val contentType = connection.contentType
        if (contentTypePredicate != null && !contentTypePredicate.apply(contentType)) {
            closeConnectionQuietly()
            throw InvalidContentTypeException(contentType, dataSpec!!)
        }

        val bytesToSkip = if (responseCode == 200 && dataSpec!!.position != 0L) dataSpec!!.position else 0

        val isCompressed: Boolean = isCompressed(connection)
        bytesToRead = if (!isCompressed) {
            if (dataSpec!!.length != C.LENGTH_UNSET.toLong()) {
                dataSpec!!.length
            } else {
                val contentLength = HttpUtil.getContentLength(
                    connection.getHeaderField(HttpHeaders.CONTENT_LENGTH),
                    connection.getHeaderField(HttpHeaders.CONTENT_RANGE)
                )
                if (contentLength != C.LENGTH_UNSET.toLong()) contentLength - bytesToSkip else C.LENGTH_UNSET.toLong()
            }
        } else {
            dataSpec!!.length
        }
        try {
            inputStream = connection.inputStream
            if (isCompressed) {
                inputStream = GZIPInputStream(inputStream)
            }
            if("https://hermes.brasilparalelo.com.br/api" == originalDataSpec.uri.toString()) {
                val response = Util.toByteArray(inputStream!!)
                val strResponse = String((response))
                val jsonObject = JSONObject(strResponse)
                try {
                    val license = jsonObject.getJSONObject("data").getJSONObject("drm_license").getString("license")
                    inputStream = ByteArrayInputStream(android.util.Base64.decode(license, android.util.Base64.DEFAULT))
                } catch (e: JSONException) {
                    closeConnectionQuietly()
                    throw Exception(
                        jsonObject.getJSONObject("data").getJSONObject("drm_license")
                            .getString("message")
                    )
                }
            }
        } catch (e: IOException) {
            closeConnectionQuietly()
            throw HttpDataSourceException(e, dataSpec!!, HttpDataSourceException.TYPE_OPEN)
        }
        opened = true
        transferStarted(dataSpec!!)
        try {
            if (!skipFully(bytesToSkip)) {
                throw DataSourceException(DataSourceException.POSITION_OUT_OF_RANGE)
            }
        } catch (e: IOException) {
            closeConnectionQuietly()
            throw HttpDataSourceException(e, dataSpec!!, HttpDataSourceException.TYPE_OPEN)
        }
        return bytesToRead
    }

    override fun read(buffer: ByteArray, offset: Int, readLength: Int): Int {
        return try {
            readInternal(buffer, offset, readLength)
        } catch (e: IOException) {
            throw HttpDataSourceException(
                e, Util.castNonNull(dataSpec), HttpDataSourceException.TYPE_READ
            )
        }
    }

    override fun close() {
        try {
            val inputStream = inputStream
            if (inputStream != null) {
                val bytesRemaining =
                    if (bytesToRead == C.LENGTH_UNSET.toLong()) C.LENGTH_UNSET.toLong() else bytesToRead - bytesRead
                maybeTerminateInputStream(connection, bytesRemaining)
                try {
                    inputStream.close()
                } catch (e: IOException) {
                    throw HttpDataSourceException(e, Util.castNonNull(dataSpec), HttpDataSourceException.TYPE_CLOSE)
                }
            }
        } finally {
            inputStream = null
            closeConnectionQuietly()
            if (opened) {
                opened = false
                transferEnded()
            }
        }
    }

    private fun makeConnection(dataSpec: DataSpec, body: JSONObject?): HttpURLConnection {
        var url = URL(dataSpec.uri.toString())
        var httpMethod: @DataSpec.HttpMethod Int = dataSpec.httpMethod
        val position = dataSpec.position
        val length = dataSpec.length
        val allowGzip = dataSpec.isFlagSet(DataSpec.FLAG_ALLOW_GZIP)
        if (!allowCrossProtocolRedirects) {
            return makeConnection(
                url,
                httpMethod,
                body,
                position,
                length,
                allowGzip,
                true,
                dataSpec.httpRequestHeaders,
                dataSpec.httpBody
            )
        }
        var redirectCount = 0
        while (redirectCount++ <= MAX_REDIRECTS) {
            val connection = makeConnection(
                url,
                httpMethod,
                body,
                position,
                length,
                allowGzip,
                false,
                dataSpec.httpRequestHeaders,
                dataSpec.httpBody
            )
            val responseCode = connection.responseCode
            val location = connection.getHeaderField("Location")
            if ((httpMethod == DataSpec.HTTP_METHOD_GET || httpMethod == DataSpec.HTTP_METHOD_HEAD)
                && (responseCode == HttpURLConnection.HTTP_MULT_CHOICE || responseCode == HttpURLConnection.HTTP_MOVED_PERM || responseCode == HttpURLConnection.HTTP_MOVED_TEMP || responseCode == HttpURLConnection.HTTP_SEE_OTHER || responseCode == HTTP_STATUS_TEMPORARY_REDIRECT || responseCode == HTTP_STATUS_PERMANENT_REDIRECT)
            ) {
                connection.disconnect()
                url = handleRedirect(url, location)
            } else if (httpMethod == DataSpec.HTTP_METHOD_POST
                && (responseCode == HttpURLConnection.HTTP_MULT_CHOICE || responseCode == HttpURLConnection.HTTP_MOVED_PERM || responseCode == HttpURLConnection.HTTP_MOVED_TEMP || responseCode == HttpURLConnection.HTTP_SEE_OTHER)
            ) {
                connection.disconnect()
                httpMethod = DataSpec.HTTP_METHOD_GET
                url = handleRedirect(url, location)
            } else {
                return connection
            }
        }
        throw NoRouteToHostException("Too many redirects: $redirectCount")
    }

    private fun makeConnection(
        url: URL,
        httpMethod: @DataSpec.HttpMethod Int,
        httpBody: JSONObject?,
        position: Long,
        length: Long,
        allowGzip: Boolean,
        followRedirects: Boolean,
        requestParameters: Map<String, String>,
        originalHttpBody: ByteArray?
    ): HttpURLConnection {
        val connection = openConnection(url)
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        val requestHeaders: MutableMap<String, String> = HashMap()
        if (defaultRequestProperties != null) {
            requestHeaders.putAll(defaultRequestProperties.snapshot)
        }
        requestHeaders.putAll(requestProperties.snapshot)
        requestHeaders.putAll(requestParameters)
        for ((key, value) in requestHeaders) {
            connection.setRequestProperty(key, value)
        }
        val rangeHeader = HttpUtil.buildRangeRequestHeader(position, length)
        if (rangeHeader != null) {
            connection.setRequestProperty(HttpHeaders.RANGE, rangeHeader)
        }
        if (userAgent != null) {
            connection.setRequestProperty(HttpHeaders.USER_AGENT, userAgent)
        }
        connection.setRequestProperty(
            HttpHeaders.ACCEPT_ENCODING,
            if (allowGzip) "gzip" else "identity"
        )
        connection.instanceFollowRedirects = followRedirects
        connection.doOutput = httpBody != null
        connection.requestMethod = DataSpec.getStringForHttpMethod(httpMethod)
        when {
            httpBody != null -> {
                connection.setFixedLengthStreamingMode(httpBody.toString().length)
                connection.connect()
                val wr = OutputStreamWriter(connection.outputStream)
                wr.write(httpBody.toString())
                wr.close()
            }
            originalHttpBody != null -> {
                connection.setFixedLengthStreamingMode(originalHttpBody.size)
                connection.connect()
                val os = connection.outputStream
                os.write(originalHttpBody)
                os.close()
            }
            else -> {
                connection.connect()
            }
        }
        return connection
    }

    private fun openConnection(url: URL): HttpURLConnection {
        return url.openConnection() as HttpURLConnection
    }

    private fun skipFully(bytesToSkip: Long): Boolean {
        var bytesToSkip = bytesToSkip
        if (bytesToSkip == 0L) {
            return true
        }
        val skipBuffer = ByteArray(4096)
        while (bytesToSkip > 0) {
            val readLength = bytesToSkip.coerceAtMost(skipBuffer.size.toLong()).toInt()
            val read = Util.castNonNull(inputStream).read(skipBuffer, 0, readLength)
            if (Thread.currentThread().isInterrupted) {
                throw InterruptedIOException()
            }
            if (read == -1) {
                return false
            }
            bytesToSkip -= read.toLong()
            bytesTransferred(read)
        }
        return true
    }

    private fun readInternal(buffer: ByteArray, offset: Int, readLength: Int): Int {
        var readLength = readLength
        if (readLength == 0) {
            return 0
        }
        if (bytesToRead != C.LENGTH_UNSET.toLong()) {
            val bytesRemaining = bytesToRead - bytesRead
            if (bytesRemaining == 0L) {
                return C.RESULT_END_OF_INPUT
            }
            readLength = Math.min(readLength.toLong(), bytesRemaining).toInt()
        }
        val read = Util.castNonNull(inputStream).read(buffer, offset, readLength)
        if (read == -1) {
            return C.RESULT_END_OF_INPUT
        }
        bytesRead += read.toLong()
        bytesTransferred(read)
        return read
    }

    private fun closeConnectionQuietly() {
        if (connection != null) {
            try {
                connection!!.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "Unexpected error while disconnecting", e)
            }
            connection = null
        }
    }

    private fun handleRedirect(originalUrl: URL, location: String?): URL {
        if (location == null) {
            throw ProtocolException("Null location redirect")
        }
        val url = URL(originalUrl, location)
        val protocol = url.protocol
        if ("https" != protocol && "http" != protocol) {
            throw ProtocolException("Unsupported protocol redirect: $protocol")
        }
        return url
    }

    private fun maybeTerminateInputStream(connection: HttpURLConnection?, bytesRemaining: Long) {

        try {
            val inputStream = connection!!.inputStream
            if (bytesRemaining == C.LENGTH_UNSET.toLong()) {
                if (inputStream.read() == -1) {
                    return
                }
            } else if (bytesRemaining <= MAX_BYTES_TO_DRAIN) {
                return
            }
            val className = inputStream.javaClass.name
            if ("com.android.okhttp.internal.http.HttpTransport\$ChunkedInputStream" == className || ("com.android.okhttp.internal.http.HttpTransport\$FixedLengthInputStream" == className)) {
                val superclass: Class<*>? = inputStream.javaClass.superclass
                val unexpectedEndOfInput = Assertions.checkNotNull(superclass).getDeclaredMethod("unexpectedEndOfInput")
                unexpectedEndOfInput.isAccessible = true
                unexpectedEndOfInput.invoke(inputStream)
            }
        } catch (ignored: Exception) { }
    }

    private fun isCompressed(connection: HttpURLConnection): Boolean {
        val contentEncoding = connection.getHeaderField("Content-Encoding")
        return "gzip".equals(contentEncoding, ignoreCase = true)
    }
}