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

use Doctrine\ORM\EntityManagerInterface;
use Klipper\Component\SecurityOauth\Model\OauthAccessTokenInterface;
use Klipper\Component\SecurityOauth\Model\OauthRefreshTokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/logout", methods={"PUT"})
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class LogoutController
{
    public function __invoke(Request $request, EntityManagerInterface $em): Response
    {
        $accessToken = $request->attributes->get('oauth_access_token_id');

        if (null !== $accessToken) {
            $this->revokeTokens($em, $accessToken);
        }

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    private function revokeTokens(EntityManagerInterface $em, string $accessToken): void
    {
        try {
            $atRepo = $em->getRepository(OauthAccessTokenInterface::class);
            $rtRepo = $em->getRepository(OauthRefreshTokenInterface::class);

            $at = $atRepo->findOneBy(['token' => $accessToken]);

            if (null !== $at) {
                $rt = $rtRepo->findOneBy(['accessToken' => $at]);

                if (null !== $rt) {
                    $em->remove($rt);
                }

                $em->remove($at);
                $em->flush();
            }
        } catch (\Throwable $e) {
            // do nothing
        }
    }
}
