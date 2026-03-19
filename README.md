# NOAuth — Multi-Provider OAuth for Nette

OAuth login with Google, Microsoft, Facebook + Google One Tap. Normalized user data.

## Installation

```bash
composer require jansuchanek/noauth
```

## Nette Integration

```neon
extensions:
    oauth: NOAuth\OAuthExtension

oauth:
    google:
        clientId: %env.GOOGLE_CLIENT_ID%
        clientSecret: %env.GOOGLE_CLIENT_SECRET%
        redirectUri: https://example.com/oauth/google
    microsoft:
        clientId: %env.MS_CLIENT_ID%
        clientSecret: %env.MS_CLIENT_SECRET%
        redirectUri: https://example.com/oauth/microsoft
    facebook:
        clientId: %env.FB_APP_ID%
        clientSecret: %env.FB_APP_SECRET%
        redirectUri: https://example.com/oauth/facebook
```

## Usage

```php
use NOAuth\OAuthManager;
use NOAuth\OAuthUser;

// Get authorization URL
$result = $manager->getAuthorizationUrl('google');
// redirect to $result['url'], store $result['state']

// Handle callback
$oauthUser = $manager->handleCallback('google', $code);
// $oauthUser->email, ->firstName, ->lastName, ->avatarUrl, ->provider, ->oauthId

// Google One Tap
$oauthUser = $manager->handleGoogleOneTap($credential);
```

## Requirements

- PHP >= 8.1
- league/oauth2-client
