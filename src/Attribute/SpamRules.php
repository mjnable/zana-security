<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

use Attribute;

/**
 * Applies the spam rules configured for a form to the handler that receives
 * it (2.24, FE-63), enforced by SpamGuardMiddleware on the route:
 *
 *     #[SpamRules('contact')]   // security.spam.forms.contact
 *
 * The form is named here, on the server, never by the request, so a bot
 * cannot choose rules that are easier to pass.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class SpamRules
{
    public function __construct(
        public string $form,
    ) {
    }
}
