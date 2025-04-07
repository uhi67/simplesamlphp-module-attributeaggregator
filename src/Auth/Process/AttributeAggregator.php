<?php

declare(strict_types=1);

/**
 * Attribute Aggregator Authentication Processing filter
 *
 * Filter for requesting the vo to give attributes to the SP.
 *
 * @author Gyula Szabó <gyufi@niif.hu>
 * @package simpleSAMLphp
 * @version $Id$
 */

namespace SimpleSAML\Module\attributeaggregator\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SAML2\Constants;

class AttributeAggregator extends ProcessingFilter
{

	/**
	 *
	 * AA IdP entityId
	 * @var string
	 */
	private $entityId = null;

	/**
	 *
	 * attributeId, the key of the user in the AA. default is eduPersonPrincipalName
	 * @var unknown_type
	 */
	private $attributeId = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";

	/**
	 *
	 * If set to TRUE, the module will throw an exception if attributeId is not found.
	 * @var boolean
	 */
	private $required = FALSE;

	/**
	 *
	 * nameIdFormat, the format of the attributeId. Default is "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	 * @var unknown_type
	 */
	private $nameIdFormat = Constants::NAMEID_PERSISTENT;


	/**
	 * Array of the requested attributes
	 * @var array
	 */
	private $attributes = [];

	/**
	 * nameFormat of attributes. Default is "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	 * @var string
	 */
	private $attributeNameFormat = Constants::NAMEFORMAT_URI;

	/**
	 * Initialize attributeaggregator filter
	 *
	 * Validates and parses the configuration
	 *
	 * @param array $config   Configuration information
	 * @param mixed $reserved For future use
	 */
	public function __construct(array $config, $reserved)
	{
		assert('is_array($config)');
		parent::__construct($config, $reserved);

		$metadata = MetaDataStorageHandler::getMetadataHandler();

		if ($config['entityId']) {
			$aameta = $metadata->getMetaData($config['entityId'], 'attributeauthority-remote');
			if (!$aameta) {
				throw new Exception(
                    'attributeaggregator: AA entityId (' . $config['entityId'] .
					') does not exist in the attributeauthority-remote metadata set.'
				);
			}
			$this->entityId = $config['entityId'];
		}
		else {
			throw new Exception(
                    'attributeaggregator: AA entityId is not specified in the configuration.'
				);
		}

		if (! empty($config["attributeId"])){
			$this->attributeId = $config["attributeId"];
		}

		if (! empty($config["required"])){
			$this->required = $config["required"];
		}

		if (!empty($config["nameIdFormat"])){
			foreach ([  Constants::NAMEID_UNSPECIFIED,
						Constants::NAMEID_PERSISTENT,
						Constants::NAMEID_TRANSIENT,
						Constants::NAMEID_ENCRYPTED] as $format) {
				$invalid = TRUE;
				if ($config["nameIdFormat"] == $format) {
					$this->nameIdFormat = $config["nameIdFormat"];
					$invalid = FALSE;
					break;
				}
			}
			if ($invalid)
				throw new Exception("attributeaggregator: Invalid nameIdFormat: ".$config["nameIdFormat"]);
		}

		if (!empty($config["attributes"])){
			if (! is_array($config["attributes"])) {
				throw new Exception("attributeaggregator: Invalid format of attributes array in the configuration");
			}
			foreach ($config["attributes"] as $attribute) {
				if (! is_array($attribute)) {
					throw new Exception("attributeaggregator: Invalid format of attributes array in the configuration");
				}
				if (array_key_exists("values", $attribute)) {
					if (! is_array($attribute["values"])) {
						throw new Exception("attributeaggregator: Invalid format of attributes array in the configuration");
					}
				}
				if (array_key_exists('multiSource', $attribute)){
					if(! preg_match('/^(merge|keep|override)$/', $attribute['multiSource']))
						throw new Exception(
                    		'attributeaggregator: Invalid multiSource value '.$attribute['multiSource'].' for '.key($attribute).'. It not mached keep, merge or override.'
					);
				}
			}
			$this->attributes = $config["attributes"];
		}

		if (!empty($config["attributeNameFormat"])){
			foreach ([  Constants::NAMEFORMAT_UNSPECIFIED,
						Constants::NAMEFORMAT_URI,
						Constants::NAMEFORMAT_BASIC] as $format) {
				$invalid = TRUE;
				if ($config["attributeNameFormat"] == $format) {
					$this->attributeNameFormat = $config["attributeNameFormat"];
					$invalid = FALSE;
					break;
				}
			}
			if ($invalid)
				throw new Exception("attributeaggregator: Invalid attributeNameFormat: ".$config["attributeNameFormat"], 1);
		}
	}

	/**
	 * Process a authentication response
	 *
	 * This function saves the state, and redirects the user to the Attribute Authority for
	 * entitlements.
	 *
	 * @param array &$state The state of the response.
	 *
	 * @return void
	 */
	public function process(array &$state): void
	{
		assert('is_array($state)');
		$state['attributeaggregator:authsourceId'] = $state["saml:sp:State"]["saml:sp:AuthId"];
		$state['attributeaggregator:entityId'] = $this->entityId;

		$state['attributeaggregator:attributeId'] = $state['Attributes'][$this->attributeId];
		$state['attributeaggregator:nameIdFormat'] = $this->nameIdFormat;

		$state['attributeaggregator:attributes'] = $this->attributes;
		$state['attributeaggregator:attributeNameFormat'] = $this->attributeNameFormat;

		if (! $state['attributeaggregator:attributeId']){
			if (! $this->required) {
				Logger::info('[attributeaggregator] This user session does not have '.$this->attributeId.', which is required for querying the AA! Continue processing.');
				Logger::debug('[attributeaggregator] Attributes are: '.var_export($state['Attributes'],true));
				SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
			}
			throw new Exception("This user session does not have ".$this->attributeId.", which is required for querying the AA! Attributes are: ".var_export($state['Attributes'],1));
		}

		$url = Module::getModuleURL('attributeaggregator/attributequery.php');
        $params = ['StateId' => $id];

        $httpUtils = new HTTP();
        $httpUtils->redirectTrustedURL($url, $params);
	}
}
