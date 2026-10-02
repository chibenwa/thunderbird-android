package app.k9mail.feature.account.oauth.data

import android.net.Uri
import app.k9mail.feature.account.oauth.domain.AccountOAuthDomainContract
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URLEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.openid.appauth.connectivity.ConnectionBuilder
import net.openid.appauth.connectivity.DefaultConnectionBuilder

internal class TokenRevocationRepository(
    private val connectionBuilder: ConnectionBuilder = DefaultConnectionBuilder.INSTANCE,
) : AccountOAuthDomainContract.TokenRevocationRepository {

    override suspend fun revoke(
        revocationEndpoint: String,
        clientId: String,
        token: String,
        tokenTypeHint: String,
    ) {
        val body = mapOf(
            "token" to token,
            "token_type_hint" to tokenTypeHint,
            "client_id" to clientId,
        ).entries.joinToString("&") { (name, value) -> "$name=${URLEncoder.encode(value, "UTF-8")}" }

        val responseCode = withContext(Dispatchers.IO) {
            val connection = connectionBuilder.openConnection(Uri.parse(revocationEndpoint))
            try {
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.outputStream.use { it.write(body.toByteArray()) }
                connection.responseCode
            } finally {
                connection.disconnect()
            }
        }

        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw IOException("Token revocation failed with HTTP status $responseCode")
        }
    }
}
