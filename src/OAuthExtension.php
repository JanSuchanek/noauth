<?php

declare(strict_types=1);

namespace NOAuth;

use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;
use Nette\Schema\Schema;

/**
 * Nette DI extension for OAuth.
 *
 * Configuration:
 *   extensions:
 *       oauth: NOAuth\OAuthExtension
 *
 *   oauth:
 *       google:
 *           clientId: %env.GOOGLE_OAUTH_CLIENT_ID%
 *           clientSecret: %env.GOOGLE_OAUTH_CLIENT_SECRET%
 *           redirectUri: %env.GOOGLE_OAUTH_REDIRECT_URI%
 *       microsoft:
 *           clientId: %env.MICROSOFT_OAUTH_CLIENT_ID%
 *           clientSecret: %env.MICROSOFT_OAUTH_CLIENT_SECRET%
 *           redirectUri: %env.MICROSOFT_OAUTH_REDIRECT_URI%
 *       facebook:
 *           clientId: %env.FACEBOOK_APP_ID%
 *           clientSecret: %env.FACEBOOK_APP_SECRET%
 *           redirectUri: %env.FACEBOOK_REDIRECT_URI%
 */
class OAuthExtension extends CompilerExtension
{
	public function getConfigSchema(): Schema
	{
		$providerSchema = Expect::structure([
			'clientId' => Expect::string(''),
			'clientSecret' => Expect::string(''),
			'redirectUri' => Expect::string(''),
		]);

		return Expect::structure([
			'google' => (clone $providerSchema),
			'microsoft' => (clone $providerSchema),
			'facebook' => (clone $providerSchema),
		]);
	}


	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();
		/** @var \stdClass $config */
		$config = $this->getConfig();

		$def = $builder->addDefinition($this->prefix('manager'))
			->setFactory(OAuthManager::class);

		foreach (['google', 'microsoft', 'facebook'] as $provider) {
			/** @var \stdClass $pc */
			$pc = $config->$provider;
			if ($pc->clientId !== '') {
				$def->addSetup('addProvider', [$provider, $pc->clientId, $pc->clientSecret, $pc->redirectUri]);
			}
		}
	}
}
