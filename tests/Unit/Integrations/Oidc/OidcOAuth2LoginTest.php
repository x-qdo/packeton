<?php

declare(strict_types=1);

namespace Packeton\Tests\Unit\Integrations\Oidc;

use Packeton\Integrations\Model\OAuth2State;
use Packeton\Integrations\Oidc\OidcOAuth2Login;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

class OidcOAuth2LoginTest extends TestCase
{
    private HttpClientInterface&MockObject $httpClient;
    private RouterInterface&MockObject $router;
    private OAuth2State&MockObject $state;
    private \Redis&MockObject $redis;
    private LoggerInterface&MockObject $logger;

    protected function setUp(): void
    {
        $this->httpClient = $this->createMock(HttpClientInterface::class);
        $this->router = $this->createMock(RouterInterface::class);
        $this->state = $this->createMock(OAuth2State::class);
        $this->redis = $this->createMock(\Redis::class);
        $this->logger = $this->createMock(LoggerInterface::class);
    }

    public function testGetDiscoveryUrlFromIssuer(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com/realms/test',
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscoveryUrl');
        $method->setAccessible(true);

        $url = $method->invoke($provider);

        $this->assertEquals(
            'https://auth.example.com/realms/test/.well-known/openid-configuration',
            $url
        );
    }

    public function testGetDiscoveryUrlFromExplicitUrl(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'discovery_url' => 'https://auth.example.com/custom/.well-known/openid-configuration',
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscoveryUrl');
        $method->setAccessible(true);

        $url = $method->invoke($provider);

        $this->assertEquals(
            'https://auth.example.com/custom/.well-known/openid-configuration',
            $url
        );
    }

    public function testGetDiscoveryUrlThrowsWhenMissing(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscoveryUrl');
        $method->setAccessible(true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('OIDC requires either discovery_url or issuer configuration');

        $method->invoke($provider);
    }

    public function testMapClaimsBasic(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'user@example.com',
            'preferred_username' => 'testuser',
            'email_verified' => true,
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertEquals('testuser', $result['user_name']);
        $this->assertEquals('user@example.com', $result['user_identifier']);
        $this->assertEquals('test-oidc:12345', $result['external_id']);
        $this->assertEquals('email', $result['_type']);
    }

    public function testMapClaimsWithCustomMapping(): void
    {
        $config = [
            'name' => 'custom-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'email' => 'mail',
                'username' => 'login',
                'sub' => 'user_id',
            ],
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'user_id' => 'custom-123',
            'mail' => 'custom@example.com',
            'login' => 'customuser',
            'email_verified' => true,
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertEquals('customuser', $result['user_name']);
        $this->assertEquals('custom@example.com', $result['user_identifier']);
        $this->assertEquals('custom-oidc:custom-123', $result['external_id']);
    }

    public function testMapClaimsFallsBackToEmailPrefix(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'john.doe@example.com',
            'email_verified' => true,
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertEquals('john.doe', $result['user_name']);
    }

    public function testMapClaimsRejectsUnverifiedEmail(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'require_email_verified' => true,
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'user@example.com',
            'email_verified' => false,
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $this->expectException(BadRequestHttpException::class);
        $this->expectExceptionMessage('OIDC email_verified is false!');

        $method->invoke($provider, $claims);
    }

    public function testMapClaimsAllowsUnverifiedEmailWhenDisabled(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'require_email_verified' => false,
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'user@example.com',
            'email_verified' => false,
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertEquals('user@example.com', $result['user_identifier']);
    }

    public function testMapRolesBasic(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'roles_map' => [
                    'admins' => ['ROLE_ADMIN', 'ROLE_MAINTAINER'],
                    'users' => ['ROLE_USER'],
                ],
            ],
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapRoles');
        $method->setAccessible(true);

        $result = $method->invoke($provider, ['admins']);

        $this->assertEquals(['ROLE_ADMIN', 'ROLE_MAINTAINER'], $result);
    }

    public function testMapRolesMergesMultipleGroups(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'roles_map' => [
                    'admins' => ['ROLE_ADMIN'],
                    'maintainers' => ['ROLE_MAINTAINER'],
                    'users' => ['ROLE_USER'],
                ],
            ],
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapRoles');
        $method->setAccessible(true);

        $result = $method->invoke($provider, ['admins', 'maintainers']);

        $this->assertContains('ROLE_ADMIN', $result);
        $this->assertContains('ROLE_MAINTAINER', $result);
    }

    public function testMapRolesReturnsEmptyForUnmappedGroups(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'roles_map' => [
                    'admins' => ['ROLE_ADMIN'],
                ],
            ],
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapRoles');
        $method->setAccessible(true);

        $result = $method->invoke($provider, ['unknown-group']);

        $this->assertEmpty($result);
    }

    public function testMapRolesReturnsEmptyWhenNoMapping(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapRoles');
        $method->setAccessible(true);

        $result = $method->invoke($provider, ['some-group']);

        $this->assertEmpty($result);
    }

    public function testMapClaimsIncludesMappedRoles(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'roles_claim' => 'groups',
                'roles_map' => [
                    'packeton-admins' => ['ROLE_ADMIN', 'ROLE_MAINTAINER'],
                ],
            ],
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'admin@example.com',
            'preferred_username' => 'admin',
            'groups' => ['packeton-admins', 'other-group'],
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertArrayHasKey('_mapped_roles', $result);
        $this->assertEquals(['ROLE_ADMIN', 'ROLE_MAINTAINER'], $result['_mapped_roles']);
    }

    public function testMapClaimsDoesNotIncludeMappedRolesWhenNoMatch(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
            'claim_mapping' => [
                'roles_claim' => 'groups',
                'roles_map' => [
                    'packeton-admins' => ['ROLE_ADMIN'],
                ],
            ],
        ];

        $provider = $this->createProvider($config);

        $claims = [
            'sub' => '12345',
            'email' => 'user@example.com',
            'preferred_username' => 'user',
            'groups' => ['unrelated-group'],
        ];

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('mapClaims');
        $method->setAccessible(true);

        $result = $method->invoke($provider, $claims);

        $this->assertArrayNotHasKey('_mapped_roles', $result);
    }

    public function testGetDiscoveryCachesResult(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $discoveryResponse = [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
        ];

        $this->redis->expects($this->once())
            ->method('get')
            ->with('oidc:discovery:test-oidc')
            ->willReturn(false);

        $this->redis->expects($this->once())
            ->method('setex')
            ->with('oidc:discovery:test-oidc', 3600, json_encode($discoveryResponse));

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($discoveryResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://auth.example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscovery');
        $method->setAccessible(true);

        $result = $method->invoke($provider);

        $this->assertEquals($discoveryResponse, $result);

        // Second call should use cache
        $result2 = $method->invoke($provider);
        $this->assertEquals($discoveryResponse, $result2);
    }

    public function testGetDiscoveryUsesRedisCache(): void
    {
        $config = [
            'name' => 'cached-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $cachedDiscovery = [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
        ];

        $this->redis->expects($this->once())
            ->method('get')
            ->with('oidc:discovery:cached-oidc')
            ->willReturn(json_encode($cachedDiscovery));

        $this->httpClient->expects($this->never())->method('request');

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscovery');
        $method->setAccessible(true);

        $result = $method->invoke($provider);

        $this->assertEquals($cachedDiscovery, $result);
    }

    public function testGetDiscoveryThrowsOnMissingFields(): void
    {
        $config = [
            'name' => 'test-oidc',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'issuer' => 'https://auth.example.com',
        ];

        $incompleteDiscovery = [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
        ];

        $this->redis->method('get')->willReturn(false);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($incompleteDiscovery);

        $this->httpClient->method('request')->willReturn($response);

        $provider = $this->createProvider($config);

        $reflection = new \ReflectionClass($provider);
        $method = $reflection->getMethod('getDiscovery');
        $method->setAccessible(true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('OIDC discovery missing required field: token_endpoint');

        $method->invoke($provider);
    }

    private function createProvider(array $config): OidcOAuth2Login
    {
        return new OidcOAuth2Login(
            $config,
            $this->httpClient,
            $this->router,
            $this->state,
            $this->redis,
            $this->logger
        );
    }
}
