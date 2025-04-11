<?php

declare(strict_types=1);

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Metadata\MetaDataStorageSource;
use SimpleSAML\Module\saml\Message;
use SimpleSAML\Session;
use SimpleSAML\Utils\Random;
use SAML2\Constants;
use SAML2\AttributeQuery;
use SAML2\SOAPClient;
use SAML2\XML\saml\NameID;


$session = Session::getSessionFromRequest();

if (!array_key_exists('StateId', $_REQUEST)) {
	throw new BadRequest(
			'[attributeaggregator] - Missing required StateId query parameter.'
	);
}

$id = $_REQUEST['StateId'];
$state = State::loadState($id, 'attributeaggregator:request');
Logger::info('[attributeaggregator] - Querying attributes from ' . $state['attributeaggregator:entityId'] );

$aaMetadata = null;

$globalConfig = Configuration::getInstance();
$metadataSources = $globalConfig->getArray('metadata.sources', []);

foreach ($metadataSources as $source) {
    try {
        $mdq = MetaDataStorageSource::getSource($source);
        $aaMetadata = $mdq->getMetaData($state['attributeaggregator:entityId'],'attributeauthority-remote');

        if ($aaMetadata) {
            if (array_keys($aaMetadata) === range(0, count($aaMetadata) - 1)) {
                $aaMetadata = $aaMetadata[0];
            }
            break;
        }
    } catch (Exception $e) {
        Logger::warning('Metadata lookup failed:' . $e->getMessage());
    }
}

if (!$aaMetadata) {
    throw new Exception(
        'attributeaggregator: AA entityId (' . $state['attributeaggregator:entityId'] .
        ') does not exist in any available metadata sources.'
    );
}


/* Find an AttributeService with SOAP binding */
$aas = $aaMetadata['AttributeService'];

if (!is_array($aas)) {
    throw new Exception("AttributeService is missing or invalid in metadata for entityId: " . var_export($aaMetadata, true));
}

for ($i=0;$i<count($aas);$i++){
	if ($aas[$i]['Binding'] == Constants::BINDING_SOAP){
		$index = $i;
		break;
	}
}

if (empty($aas[$index]['Location'])) {
	throw new Exception("Can't find the AttributeService endpoint to send the attribute query.");
}
$url = $aas[$index]['Location'];

/* nameId */
$data['nameIdValue'] = $state['attributeaggregator:attributeId'][0];
$data['nameIdFormat'] = $state['attributeaggregator:nameIdFormat'];
$data['nameIdQualifier'] = '';
$data['nameIdSPQualifier'] = '';

/* VO AttributeAuthority endpoint */
$data['url'] = $url;
$data['stateId'] = $id;


/* Building the query */

$random = new Random();
$dataId = $random->generateID();
$session->setData('attributeaggregator:data', $dataId, $data, 3600);

$nameId = new NameID();
$nameId->setFormat($data['nameIdFormat']);
$nameId->setValue($data['nameIdValue']);
$nameId->setNameQualifier($data['nameIdQualifier']);
$nameId->setSPNameQualifier($data['nameIdSPQualifier']);

if (empty($nameId->getNameQualifier())) {
	$nameId->setNameQualifier(NULL);
}
if (empty($nameId->getSPNameQualifier())) {
	$nameId->setSPNameQualifier(NULL);
}



$attributes = $state['attributeaggregator:attributes'];
$attributes_to_send = array();
foreach ($attributes as $name => $params) {
	if (array_key_exists('values', $params)){
		$attributes_to_send[$name] = $params['values'];
	}
	else {
		$attributes_to_send[$name] = array();
	}
}

$attributeNameFormat = $state['attributeaggregator:attributeNameFormat'];

$authsource = Source::getById($state["attributeaggregator:authsourceId"]);
$src = $authsource->getMetadata();
$dst = Configuration::loadFromArray($aaMetadata, 'attributeauthority-remote' . '/' . var_export($state['attributeaggregator:entityId'], true));

// Sending query
try {
	$response = sendQuery($dataId, $data['url'], $nameId, $attributes_to_send, $attributeNameFormat, $src, $dst);
} catch (Exception $e) {
	throw new Exception('[attributeaggregator] Got an exception while performing attribute query. Exception: '.get_class($e).', message: '.$e->getMessage());
}

$idpEntityId = $response->getIssuer();
if ($idpEntityId === NULL) {
	throw new Exception('Missing issuer in response.');
}
$assertions = Message::processResponse($src, $dst, $response);
$attributes_from_aa = $assertions[0]->getAttributes();
$expected_attributes = $state['attributeaggregator:attributes'];
// get attributes from response, and put it in the state.
foreach ($attributes_from_aa as $name=>$values){
	// expected?
	if (array_key_exists($name, $expected_attributes)){
		// There is in the existing attributes?
		if(array_key_exists($name, $state['Attributes'])){
			// has multiSource rule?
			if (! empty($expected_attributes[$name]['multiSource'])){
				switch ($expected_attributes[$name]['multiSource']) {
					case 'override':
						$state['Attributes'][$name] = $values;
						break;
					case 'keep':
						continue 2;
						break;
					case 'merge':
						$state['Attributes'][$name] = array_merge($state['Attributes'][$name], $values);
						break;
				}
			}
			// default: merge the attributes
			else {
				$state['Attributes'][$name] = array_merge($state['Attributes'][$name], $values);
			}
		}
		// There is not in the existing attributes, create it.
		else {
			$state['Attributes'][$name] = $values;
		}
	}
	// not expected? Put it to attributes array.
	else {
		if (!empty($state['Attributes'][$name])){
			$state['Attributes'][$name] = array_merge($state['Attributes'][$name],$values);
		}
		else
			$state['Attributes'][$name] = $values;
	}
}

Logger::debug('[attributeaggregator] - Attributes now:'.var_export($state['Attributes'],true));
ProcessingChain::resumeProcessing($state);
exit;

/**
 * build and send AttributeQuery
 */
function sendQuery($dataId, $url, $nameId, $attributes, $attributeNameFormat,$src,$dst) {
	Assert::string($dataId);
    Assert::string($url);
    Assert::isInstanceOf($nameId, NameID::class);
    Assert::isArray($attributes);

	Logger::debug('[attributeaggregator] - sending request');

    $issuer = new \SAML2\XML\saml\Issuer();
    $issuer->setValue($src->getValue('entityid'));

	$query = new AttributeQuery();
	$query->setRelayState($dataId);
	$query->setDestination($url);
	$query->setIssuer($issuer);
	$query->setNameId($nameId);
	$query->setAttributeNameFormat($attributeNameFormat);

	if (! empty($attributes)){
		$query->setAttributes($attributes);
	}

	Message::addSign($src,$dst,$query);

	if (! $query->getSignatureKey()){
		throw new Exception('[attributeaggregator] - Unable to find private key for signing attribute request.');
	}

	Logger::debug('[attributeaggregator] - sending attribute query: '.var_export($query, true));
	$binding = new SOAPClient();

	$result = $binding->send($query, $src, $dst);
	return $result;
}