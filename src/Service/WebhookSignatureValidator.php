<?php

declare(strict_types=1);

namespace Packeton\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

class WebhookSignatureValidator
{
    private const SIGNATURE_HEADER = 'X-Hub-Signature-256';
    private const SIGNATURE_PREFIX = 'sha256=';

    private ?int $matchedSecretId = null;

    public function __construct(
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function validate(Request $request, array $secrets): bool
    {
        $this->matchedSecretId = null;

        $signature = $request->headers->get(self::SIGNATURE_HEADER);
        if (empty($signature)) {
            $this->log('Missing signature header', $request);
            return false;
        }

        if (!str_starts_with($signature, self::SIGNATURE_PREFIX)) {
            $this->log('Invalid signature format', $request);
            return false;
        }

        $providedHash = substr($signature, strlen(self::SIGNATURE_PREFIX));
        $payload = $request->getContent();

        foreach ($secrets as $id => $secret) {
            $expectedHash = hash_hmac('sha256', $payload, $secret);

            if (hash_equals($expectedHash, $providedHash)) {
                $this->matchedSecretId = (int) $id;
                return true;
            }
        }

        $this->log('No matching secret found', $request);
        return false;
    }

    public function getMatchedSecretId(): ?int
    {
        return $this->matchedSecretId;
    }

    private function log(string $message, Request $request): void
    {
        $this->logger?->warning('Webhook signature validation failed: ' . $message, [
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent'),
        ]);
    }
}
