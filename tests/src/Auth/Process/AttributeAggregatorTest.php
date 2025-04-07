<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\attributeaggregator\Auth\Process;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\attributeaggregator\Auth\Process\attributeaggregator;

class AttributeAggregatorTest extends TestCase
{
    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param array $config The filter configuration.
     * @param array $request The request state.
     * @return array The state array after processing.
     */
    private static function processFilter(array $config, array $request): array
    {
        $filter = new attributeaggregator($config, null);
        $filter->process($request);
        return $request;
    }

    public function testAny(): void
    {
        $this->assertTrue(true, 'Just for travis.yml test');
    }
}
