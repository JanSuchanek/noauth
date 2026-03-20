# noauth

Multi-provider OAuth login (Google, Microsoft, Facebook).

## Key Classes
- `OAuthManager` — provider registry and flow orchestration
- `OAuthUser` — normalized user data from OAuth providers
- DI Extension: `OAuthExtension`

## Conventions
- PHP 8.2+ with `declare(strict_types=1)`
- PSR-4 autoloading in `src/`
- Nette DI Extension for service registration
- PHPStan level 9
- Part of `jansuchanek/*` on Packagist
- GitHub: https://github.com/JanSuchanek/noauth
