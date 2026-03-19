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

		/** @var array<string, mixed> $data */
		$data = $owner->toArray();

		return new OAuthUser(
			provider: $provider,
			oauthId: strval($owner->getId()), // @phpstan-ignore argument.type
			email: is_string($data['email'] ?? null) ? $data['email'] : (is_string($data['mail'] ?? null) ? $data['mail'] : (is_string($data['userPrincipalName'] ?? null) ? $data['userPrincipalName'] : '')),
			firstName: is_string($data['given_name'] ?? null) ? $data['given_name'] : (is_string($data['givenName'] ?? null) ? $data['givenName'] : (is_string($data['first_name'] ?? null) ? $data['first_name'] : (is_string($data['displayName'] ?? null) ? $data['displayName'] : ''))),
			lastName: is_string($data['family_name'] ?? null) ? $data['family_name'] : (is_string($data['surname'] ?? null) ? $data['surname'] : (is_string($data['last_name'] ?? null) ? $data['last_name'] : '')),
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

		/** @var array<string, mixed> $payload */
		$payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
		if (!$payload) {
			throw new \RuntimeException('Could not decode credential.');
		}

		$googleConfig = $this->providers['google'] ?? null;
		if ($googleConfig && strval($payload['aud'] ?? '') !== $googleConfig['clientId']) { // @phpstan-ignore argument.type
			throw new \RuntimeException('Invalid token audience.');
		}

		if (intval($payload['exp'] ?? 0) < time()) { // @phpstan-ignore argument.type
			throw new \RuntimeException('Token expired.');
		}

		return new OAuthUser(
			provider: 'google',
			oauthId: strval($payload['sub'] ?? ''), // @phpstan-ignore argument.type
			email: strval($payload['email'] ?? ''), // @phpstan-ignore argument.type
			firstName: strval($payload['given_name'] ?? ''), // @phpstan-ignore argument.type
			lastName: strval($payload['family_name'] ?? ''), // @phpstan-ignore argument.type
			avatarUrl: is_string($payload['picture'] ?? null) ? $payload['picture'] : null,
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
		if (is_array($picture) && is_array($picture['data'] ?? null)) {
			return is_string($picture['data']['url'] ?? null) ? $picture['data']['url'] : null;
		}
		return is_string($picture) ? $picture : null;
	}
}
