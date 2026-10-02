package com.fsck.k9.backends

import assertk.assertThat
import assertk.assertions.isEqualTo
import kotlin.test.Test
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationException.AuthorizationRequestErrors
import net.openid.appauth.AuthorizationException.GeneralErrors
import net.openid.appauth.AuthorizationException.TokenRequestErrors

class TokenErrorKindTest {
    @Test
    fun `connection failure should be transient`() {
        assertKind(GeneralErrors.NETWORK_ERROR, TokenErrorKind.TRANSIENT)
    }

    @Test
    fun `response that is not JSON should be transient`() {
        // e.g. 502 or 503 HTML page from a reverse proxy or load balancer
        assertKind(GeneralErrors.JSON_DESERIALIZATION_ERROR, TokenErrorKind.TRANSIENT)
    }

    @Test
    fun `server_error from the token endpoint should be transient`() {
        assertKind(TokenRequestErrors.byString("server_error"), TokenErrorKind.TRANSIENT)
    }

    @Test
    fun `temporarily_unavailable from the token endpoint should be transient`() {
        assertKind(TokenRequestErrors.byString("temporarily_unavailable"), TokenErrorKind.TRANSIENT)
    }

    @Test
    fun `invalid ID token in the refresh response should be transient`() {
        // e.g. wrong device clock
        assertKind(GeneralErrors.ID_TOKEN_VALIDATION_ERROR, TokenErrorKind.TRANSIENT)
    }

    @Test
    fun `invalid_grant should require a new login`() {
        assertKind(TokenRequestErrors.byString("invalid_grant"), TokenErrorKind.LOGIN_REQUIRED)
    }

    @Test
    fun `missing refresh token should require a new login`() {
        assertKind(AuthorizationRequestErrors.CLIENT_ERROR, TokenErrorKind.LOGIN_REQUIRED)
    }

    @Test
    fun `invalid_client should fail authentication without requiring a new login`() {
        assertKind(TokenRequestErrors.byString("invalid_client"), TokenErrorKind.AUTHENTICATION_FAILED)
    }

    private fun assertKind(exception: AuthorizationException, expected: TokenErrorKind) {
        val testSubject = exception

        val result = testSubject.toTokenErrorKind()

        assertThat(result).isEqualTo(expected)
    }
}
