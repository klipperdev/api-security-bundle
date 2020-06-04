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
use Klipper\Bundle\ApiBundle\Controller\AbstractController;
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
class RolePermissionController extends AbstractController
{
    /**
     * Get the permissions of a role.
     *
     * @param PermissionMetadataManagerInterface $pmManager The permission metadata manager
     * @param int|string                         $id        The role id
     *
     * @return Response
     *
     * @Route("/roles/{id}/permissions", methods={"GET"})
     */
    public function viewsAction(PermissionMetadataManagerInterface $pmManager, $id)
    {
        $role = $this->getRole($id, true);
        $this->addViewTransformer(new RolePermissionsTransformer($pmManager));

        return $this->view($role);
    }

    /**
     * Update the permissions of a role.
     *
     * @param PermissionMetadataManagerInterface $pmManager The permission metadata manager
     * @param int|string                         $id        The role id
     *
     * @return Response
     *
     * @Route("/roles/{id}/permissions", methods={"PATCH"})
     */
    public function updateAction(PermissionMetadataManagerInterface $pmManager, $id)
    {
        $role = $this->getRole($id, false);
        $this->addViewTransformer(new RolePermissionsTransformer($pmManager, true));

        return $this->update(Update::build(
            RolePermissionType::class,
            $role
        ));
    }

    /**
     * Get the object permissions of a role.
     *
     * @param PermissionMetadataManagerInterface $pmManager The permission metadata manager
     * @param int|string                         $id        The role id
     * @param string                             $object    The name of object metadata
     *
     * @return Response
     *
     * @Route("/roles/{id}/objects/{object}/permissions", methods={"GET"})
     */
    public function viewObjectAction(PermissionMetadataManagerInterface $pmManager, $id, string $object)
    {
        $role = $this->getRole($id, true);
        $this->addViewTransformer(new RoleObjectPermissionsTransformer($pmManager, $object));

        try {
            return $this->view($role);
        } catch (ObjectMetadataNotFoundException $e) {
            throw $this->createNotFoundException();
        }
    }

    /**
     * Update the object permissions of a role.
     *
     * @param PermissionMetadataManagerInterface $pmManager The permission metadata manager
     * @param int|string                         $id        The role id
     * @param string                             $object    The name of object metadata
     *
     * @return Response
     *
     * @Route("/roles/{id}/objects/{object}/permissions", methods={"PATCH"})
     */
    public function updateObjectAction(PermissionMetadataManagerInterface $pmManager, $id, string $object)
    {
        $role = $this->getRole($id, false);
        $this->addViewTransformer(new RoleObjectPermissionsTransformer(
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

            return $this->update($update);
        } catch (ObjectMetadataNotFoundException $e) {
            throw $this->createNotFoundException();
        }
    }

    /**
     * @param int|string $id
     */
    private function getRole($id, bool $readOnly): RoleInterface
    {
        if (class_exists(ScopeVote::class)) {
            $scopes = $readOnly ? ['meta/role'] : ['meta/role', 'meta/role.readonly'];
            $this->denyAccessUnlessGranted(new ScopeVote($scopes, false));
        }

        if (!$readOnly) {
            $this->denyAccessUnlessGranted(new PermVote('manage-permissions'));
        }

        $repo = $this->getDomain(RoleInterface::class)->getRepository();
        $repoMethod = $repo instanceof TranslatableRepositoryInterface ? 'findOneTranslatedById' : 'findOneById';
        $role = $repo->{$repoMethod}($id);

        if (null === $role) {
            throw $this->createNotFoundException();
        }

        $this->denyAccessUnlessGranted(new PermVote('view'), $role);

        return $role;
    }
}
