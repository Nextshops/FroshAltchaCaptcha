<?php declare(strict_types=1);

namespace Frosh\AltchaCaptcha\Bypass;

use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Symfony\Component\HttpFoundation\Request;

class TestBypassDecider
{
    public const CONFIG_FIELD_ENABLED = 'FroshAltchaCaptcha.config.testBypassEnabled';
    public const CONFIG_FIELD_SECRET = 'FroshAltchaCaptcha.config.testBypassSecret';
    public const CONFIG_FIELD_ROUTES = 'FroshAltchaCaptcha.config.testBypassRoutes';
    public const CONFIG_FIELD_IPS = 'FroshAltchaCaptcha.config.testBypassIps';
    public const HEADER_NAME = 'x-altcha-test-bypass';

    public function __construct(
        private readonly SystemConfigService $systemConfigService,
    ) {
    }

    public function isAllowed(Request $request): bool
    {
        $salesChannelId = $this->getSalesChannelId($request);

        if (!$this->systemConfigService->getBool(self::CONFIG_FIELD_ENABLED, $salesChannelId)) {
            return false;
        }

        $configuredSecret = \trim($this->systemConfigService->getString(self::CONFIG_FIELD_SECRET, $salesChannelId));
        if ($configuredSecret === '') {
            return false;
        }

        $providedSecret = \trim($request->headers->get(self::HEADER_NAME, ''));
        if ($providedSecret === '' || !\hash_equals($configuredSecret, $providedSecret)) {
            return false;
        }

        $currentRoute = (string) $request->attributes->get('_route', '');
        if ($currentRoute === '') {
            return false;
        }

        $allowedRoutes = $this->parseCsvList($this->systemConfigService->getString(self::CONFIG_FIELD_ROUTES, $salesChannelId));
        if ($allowedRoutes === [] || !\in_array($currentRoute, $allowedRoutes, true)) {
            return false;
        }

        $allowedIps = $this->parseCsvList($this->systemConfigService->getString(self::CONFIG_FIELD_IPS, $salesChannelId));
        if ($allowedIps === []) {
            return true;
        }

        $clientIp = \trim((string) $request->getClientIp());

        return $clientIp !== '' && \in_array($clientIp, $allowedIps, true);
    }

    private function getSalesChannelId(Request $request): ?string
    {
        $context = $request->attributes->get(PlatformRequest::ATTRIBUTE_SALES_CHANNEL_CONTEXT_OBJECT);
        if (!$context instanceof SalesChannelContext) {
            return null;
        }

        return $context->getSalesChannelId();
    }

    /**
     * @return list<string>
     */
    private function parseCsvList(string $value): array
    {
        if (\trim($value) === '') {
            return [];
        }

        $items = \array_map(static fn (string $item): string => \trim($item), \explode(',', $value));

        return \array_values(\array_filter($items, static fn (string $item): bool => $item !== ''));
    }
}

