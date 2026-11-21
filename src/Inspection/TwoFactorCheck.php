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
use Zana\Security\TwoFactorStateSwapInterface;
use Zana\Security\TwoFactorUserProviderInterface;

/**
 * security.two_factor_key (ADR-031): the key that seals second factors is
 * missing or too short while the user provider can hold second factors.
 * Without it, the sign-in page fails rather than let a password alone in.
 *
 * security.two_factor_swap (2.36): the provider holds second factors without
 * TwoFactorStateSwapInterface, so two sign-ins at the same moment can give a
 * used recovery code back (S14). A warning: sign-in still works.
 */
final readonly class TwoFactorCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $config = $application->container()->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        $key = $config->has('security.two_factor.key') ? $config->string('security.two_factor.key') : null;
        $users = $this->users($application);
        $holds = $users instanceof TwoFactorUserProviderInterface;
        $findings = [];

        if ($key === null ? $holds : strlen($key) < SecretBox::MINIMUM_KEY_LENGTH) {
            $findings[] = new Finding(
                'security.two_factor_key',
                Severity::Error,
                $key === null
                    ? 'The user provider holds second factors, but security.two_factor.key is not set, so nobody with a second factor can sign in.'
                    : 'security.two_factor.key is shorter than ' . SecretBox::MINIMUM_KEY_LENGTH . ' characters.',
                hint: 'Set it from the environment (APP_SECURITY__TWO_FACTOR__KEY), e.g. to the output of: php -r "echo bin2hex(random_bytes(32));". Keep it: changing it locks out every user with a second factor.',
            );
        }

        if ($holds && !$users instanceof TwoFactorStateSwapInterface) {
            $findings[] = new Finding(
                'security.two_factor_swap',
                Severity::Warning,
                $users::class . ' holds second factors without ' . TwoFactorStateSwapInterface::class . ', so two sign-ins at the same moment can give a used recovery code back, and count a TOTP code twice.',
                hint: 'Implement swapTwoFactorState(): UPDATE users SET two_factor = :new WHERE id = :id AND two_factor = :expected (or IS NULL), and return whether one row changed.',
            );
        }

        return $findings;
    }

    /**
     * The user provider, when there is one that can be created here.
     */
    private function users(ApplicationInterface $application): ?PasswordUserProviderInterface
    {
        $container = $application->container();
        if (!$container->has(PasswordUserProviderInterface::class)) {
            return null;
        }
        $scope = $container->createScope();
        try {
            $users = $scope->get(PasswordUserProviderInterface::class);

            return $users instanceof PasswordUserProviderInterface ? $users : null;
        } catch (\Throwable) {
            return null;   // the provider cannot be created here; other checks report that
        } finally {
            $scope->dispose();
        }
    }
}
