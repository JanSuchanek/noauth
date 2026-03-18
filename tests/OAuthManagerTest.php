<?php

declare(strict_types=1);

namespace NOAuth\Tests;

use NOAuth\OAuthManager;
use NOAuth\OAuthUser;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';

\Tester\Environment::setup();

/**
 * Tests for OAuthManager and OAuthUser.
 */
class OAuthManagerTest extends TestCase
{
	public function testAddProvider(): void
	{
		$manager = new OAuthManager();
		$manager->addProvider('google', 'client-id', 'secret', 'http://localhost/callback');

		Assert::true($manager->isConfigured('google'));
		Assert::false($manager->isConfigured('microsoft'));
	}


	public function testGetConfiguredProviders(): void
	{
		$manager = new OAuthManager();
		$manager->addProvider('google', 'id1', 'secret1', 'http://localhost/google');
		$manager->addProvider('facebook', 'id2', 'secret2', 'http://localhost/facebook');

		$providers = $manager->getConfiguredProviders();
		Assert::count(2, $providers);
		Assert::contains('google', $providers);
		Assert::contains('facebook', $providers);
	}


	public function testEmptyClientIdNotConfigured(): void
	{
		$manager = new OAuthManager();
		$manager->addProvider('google', '', 'secret', 'http://localhost/callback');

		Assert::false($manager->isConfigured('google'));
		Assert::count(0, $manager->getConfiguredProviders());
	}


	public function testGetAuthorizationUrlRequiresConfig(): void
	{
		$manager = new OAuthManager();

		Assert::exception(
			fn() => $manager->getAuthorizationUrl('google'),
			\InvalidArgumentException::class,
			"~not configured~",
		);
	}


	public function testGoogleOneTapInvalidFormat(): void
	{
		$manager = new OAuthManager();
		$manager->addProvider('google', 'id', 'secret', 'http://localhost');

		Assert::exception(
			fn() => $manager->handleGoogleOneTap('invalid-token'),
			\RuntimeException::class,
			'~Invalid credential~',
		);
	}


	public function testGoogleClientId(): void
	{
		$manager = new OAuthManager();
		Assert::same('', $manager->getGoogleClientId());

		$manager->addProvider('google', 'my-client-id', 'secret', 'http://localhost');
		Assert::same('my-client-id', $manager->getGoogleClientId());
	}


	public function testOAuthUser(): void
	{
		$user = new OAuthUser(
			provider: 'google',
			oauthId: '123',
			email: 'jan@example.com',
			firstName: 'Jan',
			lastName: 'Suchanek',
			avatarUrl: 'http://example.com/avatar.jpg',
		);

		Assert::same('google', $user->provider);
		Assert::same('jan@example.com', $user->email);
		Assert::same('Jan Suchanek', $user->getFullName());
		Assert::same('http://example.com/avatar.jpg', $user->avatarUrl);
	}
}

(new OAuthManagerTest())->run();
