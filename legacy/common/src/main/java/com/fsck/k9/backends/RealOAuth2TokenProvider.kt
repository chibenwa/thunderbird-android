package com.fsck.k9.backends

import android.content.Context
import com.fsck.k9.mail.AuthenticationFailedException
import com.fsck.k9.mail.oauth.AuthStateStorage
import com.fsck.k9.mail.oauth.OAuth2TokenProvider
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationException.AuthorizationRequestErrors
import net.openid.appauth.AuthorizationException.TokenRequestErrors
import net.openid.appauth.AuthorizationService
import net.thunderbird.legacy.logging.Log

class RealOAuth2TokenProvider(
    context: Context,
    private val authStateStorage: AuthStateStorage,
) : OAuth2TokenProvider {
    private val authService = AuthorizationService(context)
    private var requestFreshToken = false

    override val usernames: Set<String>
        get() {
            val idTokenClaims = parseAuthState().parsedIdToken?.additionalClaims.orEmpty()
            return buildSet {
                // https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#payload-claims
                // https://docs.azure.cn/en-us/entra/identity-platform/optional-claims-reference
                // requires profile scope
                idTokenClaims["preferred_username"]?.let { add(it.toString()) }
                // requires email scope
                idTokenClaims["email"]?.let { add(it.toString()) }
                // only present for v1.0 tokens
                idTokenClaims["unique_name"]?.let { add(it.toString()) }
                // requires profile scope
                idTokenClaims["upn"]?.let { add(it.toString()) }
                idTokenClaims["verified_primary_email"]?.let { verifiedPrimaryEmail ->
                    when (verifiedPrimaryEmail) {
                        is List<*> -> addAll(verifiedPrimaryEmail.map { it.toString() })
                        else -> add(verifiedPrimaryEmail.toString())
                    }
                }
                idTokenClaims["verified_secondary_email"]?.let { verifiedSecondaryEmail ->
                    when (verifiedSecondaryEmail) {
                        is List<*> -> addAll(verifiedSecondaryEmail.map { it.toString() })
                        else -> add(verifiedSecondaryEmail.toString())
                    }
                }
            }
        }

    @Suppress("TooGenericExceptionCaught")
    override fun getToken(timeoutMillis: Long): String {
        val latch = CountDownLatch(1)
        var token: String? = null
        var exception: AuthorizationException? = null

        val authState = parseAuthState()
        if (requestFreshToken) {
            authState.needsTokenRefresh = true
        }

        val oldAccessToken = authState.accessToken

        val completed = try {
            authState.performActionWithFreshTokens(
                authService,
            ) { accessToken: String?, _, authException: AuthorizationException? ->
                token = accessToken
                exception = authException

                latch.countDown()
            }

            latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (e: Exception) {
            throw IOException("Failed to fetch an access token", e)
        }

        if (!completed) {
            throw IOException("Timed out while fetching an access token")
        }

        val authException = exception
        if (authException != null) {
            when (authException.toTokenErrorKind()) {
                TokenErrorKind.TRANSIENT -> throw IOException("Error while fetching an access token", authException)
                TokenErrorKind.AUTHENTICATION_FAILED -> Unit
                TokenErrorKind.LOGIN_REQUIRED -> {
                    Log.w(authException, "Refresh token rejected. Clearing authorization state.")

                    authStateStorage.updateAuthorizationState(authorizationState = null)
                }
            }

            throw AuthenticationFailedException(
                message = "Failed to fetch an access token",
                throwable = authException,
                messageFromServer = authException.error,
            )
        } else if (token != oldAccessToken) {
            requestFreshToken = false
            authStateStorage.updateAuthorizationState(authorizationState = authState.jsonSerializeString())
        }

        return token ?: throw AuthenticationFailedException("Failed to fetch an access token")
    }

    override fun invalidateToken() {
        requestFreshToken = true
    }

    private fun parseAuthState(): AuthState {
        return authStateStorage
            .getAuthorizationState()
            ?.let { AuthState.jsonDeserialize(it) }
            ?: throw AuthenticationFailedException("Login required")
    }
}

internal enum class TokenErrorKind {
    /** Network, server or proxy failure: keep the authorization state and retry later. */
    TRANSIENT,

    /** Explicit OAuth error that does not invalidate the refresh token. */
    AUTHENTICATION_FAILED,

    /** The refresh token can no longer be used: the user has to sign in again. */
    LOGIN_REQUIRED,
}

internal fun AuthorizationException.toTokenErrorKind(): TokenErrorKind {
    return when (this) {
        TokenRequestErrors.INVALID_GRANT,
        // AppAuth's error when the access token has expired and there is no refresh token
        AuthorizationRequestErrors.CLIENT_ERROR,
        -> TokenErrorKind.LOGIN_REQUIRED

        TokenRequestErrors.INVALID_REQUEST,
        TokenRequestErrors.INVALID_CLIENT,
        TokenRequestErrors.UNAUTHORIZED_CLIENT,
        TokenRequestErrors.UNSUPPORTED_GRANT_TYPE,
        TokenRequestErrors.INVALID_SCOPE,
        TokenRequestErrors.CLIENT_ERROR,
        -> TokenErrorKind.AUTHENTICATION_FAILED

        // Includes 5xx pages that are not JSON (JSON_DESERIALIZATION_ERROR) and unknown error codes such as
        // server_error or temporarily_unavailable (TokenRequestErrors.OTHER)
        else -> TokenErrorKind.TRANSIENT
    }
}
