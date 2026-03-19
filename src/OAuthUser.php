<?php

declare(strict_types=1);

namespace NOAuth;

/**
 * Normalized user data from any OAuth provider.
 */
class OAuthUser
{
	public function __construct(
		public readonly string $provider,
		public readonly string $oauthId,
		public readonly string $email,
		public readonly string $firstName,
		public readonly string $lastName,
		public readonly ?string $avatarUrl = null,
		/** @var array<string, mixed> */
		public readonly array $raw = [],
	) {}


	public function getFullName(): string
	{
		return trim("{$this->firstName} {$this->lastName}");
	}
}
