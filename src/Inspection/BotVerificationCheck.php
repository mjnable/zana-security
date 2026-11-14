<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Router;
use Zana\Security\Attribute\VerifyHuman;
use Zana\Security\Bot\BotVerifierInterface;
use Zana\Security\Bot\FakeBotVerifier;
use Zana\Security\Bot\NullBotVerifier;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Middleware\BotVerificationMiddleware;

/**
 * security.bot_verification (2.25, FE-64): bot verification that would
 * verify nothing. Errors with security.strict, warnings otherwise, except
 * where noted:
 *
 * - #[VerifyHuman] with no BotVerificationMiddleware on its route;
 * - #[VerifyHuman] and no BotVerifierInterface registered, so every request
 *   to it is refused;
 * - in production, a verifier that accepts everything (NullBotVerifier,
 *   FakeBotVerifier);
 * - security.bot.on_unavailable or .hostnames that cannot be used;
 * - always a warning: minimumScore with a provider that gives no score, or a
 *   route that receives no POST, PUT, PATCH or DELETE.
 */
final readonly class BotVerificationCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        $strict = SecurityRules::severity($application);
        $findings = [];

        $unavailable = $config->get('security.bot.on_unavailable', 'refuse');
        if ($unavailable !== 'refuse' && $unavailable !== 'allow') {
            $findings[] = new Finding('security.bot_verification', $strict, 'security.bot.on_unavailable is ' . json_encode($unavailable) . ', not "refuse" or "allow".', hint: 'Leave it unset to refuse requests while the provider cannot be reached.', security: true);
        }
        $hostnames = $config->get('security.bot.hostnames', []);
        if (!is_array($hostnames) || !array_is_list($hostnames) || array_filter($hostnames, static fn (mixed $h): bool => is_string($h) && preg_match('/^[a-z0-9.-]+$/i', $h) === 1) !== $hostnames) {
            $findings[] = new Finding('security.bot_verification', $strict, 'security.bot.hostnames is not a list of host names, such as ["www.example.com"].', security: true);
        }

        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            return $findings;
        }
        $router = $container->get(Router::class);
        assert($router instanceof Router);
        $verifier = null;
        $resolved = false;

        foreach ($router->routes() as $route) {
            $rule = HandlerReflection::firstAttribute($route->handler, VerifyHuman::class);
            if ($rule === null) {
                continue;
            }
            if (!$resolved) {
                $resolved = true;
                $verifier = $container->has(BotVerifierInterface::class) ? $container->get(BotVerifierInterface::class) : null;
                $findings = [...$findings, ...self::verifierFindings($verifier, $application, $strict)];
            }
            $where = implode('|', $route->methods) . ' ' . $route->path;
            $file = HandlerReflection::location($route->handler);
            if (!RouteAccess::has($route->getMiddleware(), BotVerificationMiddleware::class)) {
                $findings[] = new Finding(
                    'security.bot_verification',
                    $strict,
                    "{$where} has #[VerifyHuman], but BotVerificationMiddleware is not on the route, so no token is verified.",
                    $file,
                    hint: 'Add BotVerificationMiddleware to the route or its group: middleware: [BotVerificationMiddleware::class] in #[Route].',
                    security: true,
                );
            }
            if ($rule->minimumScore !== null && $verifier instanceof BotVerifierInterface && !$verifier->scores()) {
                $findings[] = new Finding(
                    'security.bot_verification',
                    Severity::Warning,
                    "{$where} asks for a minimum score of {$rule->minimumScore}, but " . $verifier::class . ' gives no score, so it is never applied.',
                    $file,
                    hint: 'Use a provider that scores, such as reCAPTCHA v3, or remove minimumScore.',
                    security: true,
                );
            }
            if (array_intersect($route->methods, ['POST', 'PUT', 'PATCH', 'DELETE']) === []) {
                $findings[] = new Finding(
                    'security.bot_verification',
                    Severity::Warning,
                    "{$where} has #[VerifyHuman], but receives no POST, PUT, PATCH or DELETE, which is all that is verified.",
                    $file,
                    hint: 'Put #[VerifyHuman] on the handler that receives the form.',
                    security: true,
                );
            }
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private static function verifierFindings(mixed $verifier, ApplicationInterface $application, Severity $strict): array
    {
        if (!$verifier instanceof BotVerifierInterface) {
            return [new Finding(
                'security.bot_verification',
                $strict,
                'Routes use #[VerifyHuman], but no bot verifier is registered, so every request to them is refused.',
                hint: 'Install mj-zana/captcha and set captcha.provider, or register your own ' . BotVerifierInterface::class . '.',
                security: true,
            )];
        }
        if (($verifier instanceof NullBotVerifier || $verifier instanceof FakeBotVerifier) && $application->environment()->isProduction()) {
            return [new Finding(
                'security.bot_verification',
                $strict,
                'The bot verifier in production is ' . $verifier::class . ', which answers without asking a provider, so #[VerifyHuman] stops no bot.',
                hint: 'Register a real provider in production, such as mj-zana/captcha with captcha.provider.',
                security: true,
            )];
        }

        return [];
    }
}
