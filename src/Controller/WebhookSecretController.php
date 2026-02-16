<?php

declare(strict_types=1);

namespace Packeton\Controller;

use Doctrine\Persistence\ManagerRegistry;
use Packeton\Attribute\Vars;
use Packeton\Entity\WebhookSecret;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/webhook-secrets')]
#[IsGranted('ROLE_ADMIN')]
class WebhookSecretController extends AbstractController
{
    public function __construct(
        protected ManagerRegistry $registry,
    ) {
    }

    #[Route('', name: 'webhook_secret_index')]
    public function indexAction(): Response
    {
        $secrets = $this->registry->getRepository(WebhookSecret::class)->findAllActive();

        return $this->render('webhook_secret/index.html.twig', [
            'secrets' => $secrets,
        ]);
    }

    #[Route('/create', name: 'webhook_secret_create', methods: ['GET', 'POST'])]
    public function createAction(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $name = trim($request->request->get('name', ''));

            if (empty($name)) {
                $this->addFlash('error', 'Name is required');
                return $this->render('webhook_secret/create.html.twig');
            }

            $secret = new WebhookSecret();
            $secret->setName($name);
            $generatedSecret = WebhookSecret::generateSecret();
            $secret->setSecret($generatedSecret);

            $em = $this->registry->getManager();
            $em->persist($secret);
            $em->flush();

            return $this->render('webhook_secret/show_secret.html.twig', [
                'secret' => $secret,
                'generatedSecret' => $generatedSecret,
            ]);
        }

        return $this->render('webhook_secret/create.html.twig');
    }

    #[Route('/{id}/delete', name: 'webhook_secret_delete', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function deleteAction(Request $request, #[Vars] WebhookSecret $secret): Response
    {
        if (!$this->isCsrfTokenValid('webhook_secret_delete', $request->request->get('_token'))) {
            $this->addFlash('error', 'Invalid CSRF token');
            return new RedirectResponse($this->generateUrl('webhook_secret_index'));
        }

        $em = $this->registry->getManager();
        $em->remove($secret);
        $em->flush();

        $this->addFlash('success', 'Webhook secret deleted');
        return new RedirectResponse($this->generateUrl('webhook_secret_index'));
    }
}
