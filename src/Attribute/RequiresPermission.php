<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

/**
 * The handler needs an authenticated user (otherwise 401) who has this
 * permission (otherwise 403). Repeatable; every permission is required.
 *
 * With a scope (2.17), the permission is checked where the route points:
 *
 *     #[Route('/events/{eventId}/scan', methods: ['POST'], middleware: [AuthorizationMiddleware::class])]
 *     #[RequiresPermission('tickets.scan', scope: 'event')]   // the user's roles at that event, and its organization's
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION | \Attribute::IS_REPEATABLE)]
final readonly class RequiresPermission
{
    /**
     * @param string|null $scope A scope type (2.17): the permission is checked in that scope, whose id is
     *                           the route parameter $parameter
     * @param string|null $parameter The route parameter holding the scope's id; "{$scope}Id" by default
     */
    public function __construct(
        public string $permission,
        public ?string $scope = null,
        public ?string $parameter = null,
    ) {
    }

    public function parameter(): ?string
    {
        return $this->scope === null ? null : ($this->parameter ?? "{$this->scope}Id");
    }
}
