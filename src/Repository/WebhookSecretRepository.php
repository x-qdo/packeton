<?php

declare(strict_types=1);

namespace Packeton\Repository;

use Doctrine\ORM\EntityRepository;
use Packeton\Entity\WebhookSecret;

/**
 * @extends EntityRepository<WebhookSecret>
 */
class WebhookSecretRepository extends EntityRepository
{
    /**
     * @return WebhookSecret[]
     */
    public function findAllActive(): array
    {
        return $this->createQueryBuilder('ws')
            ->orderBy('ws.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * @return string[]
     */
    public function findAllSecrets(): array
    {
        $results = $this->createQueryBuilder('ws')
            ->select('ws.id, ws.secret')
            ->getQuery()
            ->getResult();

        $secrets = [];
        foreach ($results as $row) {
            $secrets[$row['id']] = $row['secret'];
        }

        return $secrets;
    }
}
