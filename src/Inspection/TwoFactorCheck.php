<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Security\Internal\SecretBox;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\TwoFactorUserProviderInterface;

/**
 * security.two_factor_key (ADR-031): the key that seals second factors is
 * missing or too short while the user provider can hold second factors.
 * Without it, the sign-in page fails rather than let a password alone in.
 */
final readonly class TwoFactorCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        $key = $config->has('security.two_factor.key') ? $config->string('security.two_factor.key') : null;
        if ($key !== null && strlen($key) >= SecretBox::MINIMUM_KEY_LENGTH) {
            return [];
        }
        if ($key === null && !$this->usersHoldSecondFactors($application)) {
            return [];
        }

        return [new Finding(
            'security.two_factor_key',
            Severity::Error,
            $key === null
                ? 'The user provider holds second factors, but security.two_factor.key is not set, so nobody with a second factor can sign in.'
                : 'security.two_factor.key is shorter than ' . SecretBox::MINIMUM_KEY_LENGTH . ' characters.',
            hint: 'Set it from the environment (APP_SECURITY__TWO_FACTOR__KEY), e.g. to the output of: php -r "echo bin2hex(random_bytes(32));". Keep it: changing it locks out every user with a second factor.',
        )];
    }

    private function usersHoldSecondFactors(ApplicationInterface $application): bool
    {
        $container = $application->container();
        if (!$container->has(PasswordUserProviderInterface::class)) {
            return false;
        }
        $scope = $container->createScope();
        try {
            return $scope->get(PasswordUserProviderInterface::class) instanceof TwoFactorUserProviderInterface;
        } catch (\Throwable) {
            return false;   // the provider cannot be created here; other checks report that
        } finally {
            $scope->dispose();
        }
    }
}
