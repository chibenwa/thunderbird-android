package app.k9mail.feature.account.oauth.domain.usecase

import android.net.Uri
import app.k9mail.feature.account.oauth.domain.AccountOAuthDomainContract
import assertk.assertThat
import assertk.assertions.containsExactly
import assertk.assertions.isEmpty
import kotlinx.coroutines.test.runTest
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.TokenRequest
import net.openid.appauth.TokenResponse
import net.thunderbird.core.common.oauth.OAuthConfiguration
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class RevokeOAuthTokensTest {
    private val repository = FakeTokenRevocationRepository()

    @Test
    fun `should revoke the refresh token`() = runTest {
        val testSubject = RevokeOAuthTokens(repository, configurationProvider = { oAuthConfiguration })

        testSubject.execute(HOSTNAME, authorizationState(accessToken = "access", refreshToken = "refresh"))

        assertThat(repository.revocations).containsExactly(
            Revocation(REVOCATION_ENDPOINT, CLIENT_ID, "refresh", "refresh_token"),
        )
    }

    @Test
    fun `should revoke the access token when there is no refresh token`() = runTest {
        val testSubject = RevokeOAuthTokens(repository, configurationProvider = { oAuthConfiguration })

        testSubject.execute(HOSTNAME, authorizationState(accessToken = "access", refreshToken = null))

        assertThat(repository.revocations).containsExactly(
            Revocation(REVOCATION_ENDPOINT, CLIENT_ID, "access", "access_token"),
        )
    }

    @Test
    fun `should do nothing without revocation endpoint`() = runTest {
        val testSubject = RevokeOAuthTokens(
            repository,
            configurationProvider = { oAuthConfiguration.copy(revocationEndpoint = null) },
        )

        testSubject.execute(HOSTNAME, authorizationState(accessToken = "access", refreshToken = "refresh"))

        assertThat(repository.revocations).isEmpty()
    }

    @Test
    fun `should do nothing without OAuth configuration`() = runTest {
        val testSubject = RevokeOAuthTokens(repository, configurationProvider = { null })

        testSubject.execute(HOSTNAME, authorizationState(accessToken = "access", refreshToken = "refresh"))

        assertThat(repository.revocations).isEmpty()
    }

    private fun authorizationState(accessToken: String, refreshToken: String?): String {
        val configuration = AuthorizationServiceConfiguration(
            Uri.parse("https://example.com/authorize"),
            Uri.parse("https://example.com/token"),
        )
        val tokenRequest = TokenRequest.Builder(configuration, CLIENT_ID)
            .setGrantType(TokenRequest.GRANT_TYPE_PASSWORD)
            .build()
        val tokenResponse = TokenResponse.Builder(tokenRequest)
            .setAccessToken(accessToken)
            .setRefreshToken(refreshToken)
            .build()

        return AuthState().apply { update(tokenResponse, null) }.jsonSerializeString()
    }

    private data class Revocation(
        val revocationEndpoint: String,
        val clientId: String,
        val token: String,
        val tokenTypeHint: String,
    )

    private class FakeTokenRevocationRepository : AccountOAuthDomainContract.TokenRevocationRepository {
        val revocations = mutableListOf<Revocation>()

        override suspend fun revoke(
            revocationEndpoint: String,
            clientId: String,
            token: String,
            tokenTypeHint: String,
        ) {
            revocations.add(Revocation(revocationEndpoint, clientId, token, tokenTypeHint))
        }
    }

    private companion object {
        const val HOSTNAME = "imap.example.com"
        const val CLIENT_ID = "client-id"
        const val REVOCATION_ENDPOINT = "https://example.com/revoke"

        val oAuthConfiguration = OAuthConfiguration(
            clientId = CLIENT_ID,
            scopes = listOf("openid"),
            authorizationEndpoint = "https://example.com/authorize",
            tokenEndpoint = "https://example.com/token",
            redirectUri = "app://oauth2redirect",
            revocationEndpoint = REVOCATION_ENDPOINT,
        )
    }
}
