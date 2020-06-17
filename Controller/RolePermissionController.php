<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Bundle\ApiSecurityBundle\Controller;

use Klipper\Bundle\ApiBundle\Action\Update;
use Klipper\Bundle\ApiBundle\Controller\ControllerHelper;
use Klipper\Bundle\ApiBundle\View\Transformer\RoleObjectPermissionsTransformer;
use Klipper\Bundle\ApiBundle\View\Transformer\RolePermissionsTransformer;
use Klipper\Component\DoctrineExtensionsExtra\Entity\Repository\Traits\TranslatableRepositoryInterface;
use Klipper\Component\Metadata\Exception\ObjectMetadataNotFoundException;
use Klipper\Component\MetadataExtensions\Form\Type\RoleObjectPermissionType;
use Klipper\Component\MetadataExtensions\Form\Type\RolePermissionType;
use Klipper\Component\MetadataExtensions\Permission\PermissionMetadataManagerInterface;
use Klipper\Component\Security\Model\RoleInterface;
use Klipper\Component\Security\Permission\PermVote;
use Klipper\Component\SecurityOauth\Scope\ScopeVote;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Role Permission controller.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class RolePermissionController
{
    /**
     * Get the permissions of a role.
     *
     * @param int|string $id The role id
     *
     * @Route("/roles/{id}/permissions", methods={"GET"})
     */
    public function viewsAction(
        ControllerHelper $helper,
        PermissionMetadataManagerInterface $pmManager,
        $id
    ): Response {
        $role = $this->getRole($helper, $id, true);
        $helper->addViewTransformer(new RolePermissionsTransformer($pmManager));

        return $helper->view($role);
    }

    /**
     * Update the permissions of a role.
     *
     * @param int|string $id The role id
     *
     * @Route("/roles/{id}/permissions", methods={"PATCH"})
     */
    public function updateAction(
        ControllerHelper $helper,
        PermissionMetadataManagerInterface $pmManager,
        $id
    ): Response {
        $role = $this->getRole($helper, $id, false);
        $helper->addViewTransformer(new RolePermissionsTransformer($pmManager, true));

        return $helper->update(Update::build(
            RolePermissionType::class,
            $role
        ));
    }

    /**
     * Get the object permissions of a role.
     *
     * @param int|string $id     The role id
     * @param string     $object The name of object metadata
     *
     * @Route("/roles/{id}/objects/{object}/permissions", methods={"GET"})
     */
    public function viewObjectAction(
        ControllerHelper $helper,
        PermissionMetadataManagerInterface $pmManager,
        $id,
        string $object
    ): Response {
        $role = $this->getRole($helper, $id, true);
        $helper->addViewTransformer(new RoleObjectPermissionsTransformer($pmManager, $object));

        try {
            return $helper->view($role);
        } catch (ObjectMetadataNotFoundException $e) {
            throw $helper->createNotFoundException();
        }
    }

    /**
     * Update the object permissions of a role.
     *
     * @param int|string $id     The role id
     * @param string     $object The name of object metadata
     *
     * @Route("/roles/{id}/objects/{object}/permissions", methods={"PATCH"})
     */
    public function updateObjectAction(
        ControllerHelper $helper,
        PermissionMetadataManagerInterface $pmManager,
        $id,
        string $object
    ): Response {
        $role = $this->getRole($helper, $id, false);
        $helper->addViewTransformer(new RoleObjectPermissionsTransformer(
            $pmManager,
            $object,
            true
        ));

        try {
            $update = Update::build(RoleObjectPermissionType::class, $role);
            $update->setMethod(Request::METHOD_PATCH);
            $update->setOptions([
                'object' => $object,
            ]);

            return $helper->update($update);
        } catch (ObjectMetadataNotFoundException $e) {
            throw $helper->createNotFoundException();
        }
    }

    /**
     * @param int|string $id
     */
    private function getRole(
        ControllerHelper $helper,
        $id,
        bool $readOnly
    ): RoleInterface {
        if (class_exists(ScopeVote::class)) {
            $scopes = $readOnly ? ['meta/role'] : ['meta/role', 'meta/role.readonly'];
            $helper->denyAccessUnlessGranted(new ScopeVote($scopes, false));
        }

        if (!$readOnly) {
            $helper->denyAccessUnlessGranted(new PermVote('manage-permissions'));
        }

        $repo = $helper->getRepository(RoleInterface::class);
        $repoMethod = $repo instanceof TranslatableRepositoryInterface ? 'findOneTranslatedById' : 'findOneById';
        $role = $repo->{$repoMethod}($id);

        if (null === $role) {
            throw $helper->createNotFoundException();
        }

        $helper->denyAccessUnlessGranted(new PermVote('view'), $role);

        return $role;
    }
}
