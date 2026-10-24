<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * An authenticated user. The application implements it.
 */
interface UserInterface
{
    /**
     * The identifier tokens carry as their subject.
     */
    public function identifier(): string;

    /**
     * @return list<string>
     */
    public function roles(): array;
}
