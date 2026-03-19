<?php

declare(strict_types=1);

namespace NOAuth;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\GenericProvider;

/**
 * Multi-provider OAuth manager.
 *
 * Handles provider instantiation, authorization URLs, callback processing,
 * and normalizes user data from different providers.
 */
class OAuthManager
{
	/** @var array<string, array{clientId: string, clientSecret: string, redirectUri: string}> */
	private array $providers = [];


	/**
	 * Register a provider with its credentials.
	 */
	public function addProvider(string $name, string $clientId, string $clientSecret, string $redirectUri): self
	{
		$this->providers[$name] = [
			'clientId' => $clientId,
			'clientSecret' => $clientSecret,
			'redirectUri' => $redirectUri,
		];
		return $this;
	}


	/**
	 * Is the provider configured?
	 */
	public function isConfigured(string $provider): bool
	{
		return isset($this->providers[$provider]) && $this->providers[$provider]['clientId'] !== '';
	}


	/**
	 * Get available configured providers.
	 *
	 * @return list<string>
	 */
	public function getConfiguredProviders(): array
	{
		return array_keys(array_filter($this->providers, fn($p) => $p['clientId'] !== ''));
	}


	/**
	 * Get authorization URL for the given provider.
	 *
	 * @return array{url: string, state: string}
	 */
	public function getAuthorizationUrl(string $provider): array
	{
		$p = $this->getLeagueProvider($provider);

		$options = match ($provider) {
			'google' => ['scope' => ['openid', 'email', 'profile']],
			'microsoft' => ['scope' => ['openid', 'profile', 'email', 'User.Read']],
			'facebook' => ['scope' => ['email']],
			default => [],
		};

		$url = $p->getAuthorizationUrl($options);

		return [
			'url' => $url,
			'state' => $p->getState(),
		];
	}


	/**
	 * Handle OAuth callback — exchange code for user data.
	 */
	public function handleCallback(string $provider, string $code): OAuthUser
	{
		$p = $this->getLeagueProvider($provider);
		$token = $p->getAccessToken('authorization_code', ['code' => $code]);
		/** @var \League\OAuth2\Client\Token\AccessToken $token */
		$owner = $p->getResourceOwner($token);

		$data = $owner->toArray();

		return new OAuthUser(
			provider: $provider,
			oauthId: (string) $owner->getId(),
			email: $data['email'] ?? $data['mail'] ?? $data['userPrincipalName'] ?? '',
			firstName: $data['given_name'] ?? $data['givenName'] ?? $data['first_name'] ?? ($data['displayName'] ?? ''),
			lastName: $data['family_name'] ?? $data['surname'] ?? $data['last_name'] ?? '',
			avatarUrl: $this->extractAvatar($data),
			raw: $data,
		);
	}


	/**
	 * Handle Google One Tap credential (JWT ID token).
	 */
	public function handleGoogleOneTap(string $credential): OAuthUser
	{
		$parts = explode('.', $credential);
		if (count($parts) !== 3) {
			throw new \RuntimeException('Invalid credential format.');
		}

		$payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
		if (!$payload) {
			throw new \RuntimeException('Could not decode credential.');
		}

		$googleConfig = $this->providers['google'] ?? null;
		if ($googleConfig && ($payload['aud'] ?? '') !== $googleConfig['clientId']) {
			throw new \RuntimeException('Invalid token audience.');
		}

		if (($payload['exp'] ?? 0) < time()) {
			throw new \RuntimeException('Token expired.');
		}

		return new OAuthUser(
			provider: 'google',
			oauthId: $payload['sub'] ?? '',
			email: $payload['email'] ?? '',
			firstName: $payload['given_name'] ?? '',
			lastName: $payload['family_name'] ?? '',
			avatarUrl: $payload['picture'] ?? null,
			raw: $payload,
		);
	}


	/**
	 * Get the Google client ID (for One Tap JS).
	 */
	public function getGoogleClientId(): string
	{
		return $this->providers['google']['clientId'] ?? '';
	}


	/**
	 * Create a League OAuth2 provider instance.
	 */
	private function getLeagueProvider(string $name): AbstractProvider
	{
		$config = $this->providers[$name] ?? throw new \InvalidArgumentException("OAuth provider '{$name}' not configured.");

		return match ($name) {
			'google' => new Google([
				'clientId' => $config['clientId'],
				'clientSecret' => $config['clientSecret'],
				'redirectUri' => $config['redirectUri'],
			]),
			'microsoft' => new GenericProvider([
				'clientId' => $config['clientId'],
				'clientSecret' => $config['clientSecret'],
				'redirectUri' => $config['redirectUri'],
				'urlAuthorize' => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize',
				'urlAccessToken' => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
				'urlResourceOwnerDetails' => 'https://graph.microsoft.com/v1.0/me',
				'scopes' => 'openid profile email User.Read',
				'scopeSeparator' => ' ',
			]),
			'facebook' => new Facebook([
				'clientId' => $config['clientId'],
				'clientSecret' => $config['clientSecret'],
				'redirectUri' => $config['redirectUri'],
				'graphApiVersion' => 'v18.0',
			]),
			default => throw new \InvalidArgumentException("Unknown OAuth provider: {$name}"),
		};
	}


	/**
	 * @param array<string, mixed> $data
	 */
	private function extractAvatar(array $data): ?string
	{
		$picture = $data['picture'] ?? null;
		if (is_array($picture)) {
			return $picture['data']['url'] ?? null;
		}
		return $picture;
	}
}
