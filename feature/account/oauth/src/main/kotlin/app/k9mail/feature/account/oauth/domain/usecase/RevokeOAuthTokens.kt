package app.k9mail.feature.account.oauth.domain.usecase

import app.k9mail.feature.account.common.domain.entity.AuthorizationState
import app.k9mail.feature.account.oauth.data.toAuthState
import app.k9mail.feature.account.oauth.domain.AccountOAuthDomainContract
import app.k9mail.feature.account.oauth.domain.AccountOAuthDomainContract.UseCase.RevokeOAuthTokens
import net.thunderbird.core.common.oauth.OAuthConfigurationProvider

internal class RevokeOAuthTokens(
    private val repository: AccountOAuthDomainContract.TokenRevocationRepository,
    private val configurationProvider: OAuthConfigurationProvider,
) : RevokeOAuthTokens {
    override suspend fun execute(hostname: String, authorizationState: String) {
        val configuration = configurationProvider.getConfiguration(hostname) ?: return
        val revocationEndpoint = configuration.revocationEndpoint ?: return
        val authState = AuthorizationState(value = authorizationState).toAuthState()

        // Revoking the refresh token also revokes the access tokens of the same grant (RFC 7009, section 2.1)
        val refreshToken = authState.refreshToken
        val accessToken = authState.accessToken
        if (refreshToken != null) {
            repository.revoke(revocationEndpoint, configuration.clientId, refreshToken, "refresh_token")
        } else if (accessToken != null) {
            repository.revoke(revocationEndpoint, configuration.clientId, accessToken, "access_token")
        }
    }
}
