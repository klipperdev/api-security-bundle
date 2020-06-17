<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Bundle\ApiSecurityBundle\DependencyInjection;

use Klipper\Bundle\ApiBundle\Util\ControllerDefinitionUtil;
use Klipper\Bundle\ApiSecurityBundle\Controller\LogoutController;
use Klipper\Bundle\ApiSecurityBundle\Controller\RolePermissionController;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class KlipperApiSecurityExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        ControllerDefinitionUtil::set($container, RolePermissionController::class);
        ControllerDefinitionUtil::set($container, LogoutController::class);
    }
}
