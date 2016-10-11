<?php
require_once dirname(__FILE__) . "/../../../../core/php/core.inc.php";
include_file('core', 'authentification', 'php');
if (!jeedom::apiAccess(init('apikey'))) {
	echo 'Clef API non valide, vous n\'êtes pas autorisé à effectuer cette action';
	die();
}
$eqLogic = eqLogic::byId(init('eqLogic_id'));
if (!is_object($eqLogic)) {
	echo 'Impossible de trouver l\'équipement correspondant à : ' . init('eqLogic_id');
	exit();
}

if (!isConnect()) {
	echo 'Vous ne pouvez appeller cette page sans être connecté. Veuillez vous connecter <a href=' . network::getNetworkAccess() . '/index.php>ici</a> avant et refaire l\'opération de synchronisation';
	die();
}

$provider = $eqLogic->getProvider();

if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
	unset($_SESSION['oauth2state']);
	exit('Invalid state');
}
try {
	$accessToken = $provider->getAccessToken('authorization_code', [
		'code' => $_GET['code'],
	]);
	$eqLogic->setConfiguration('accessToken', $accessToken->jsonSerialize());
	$eqLogic->save();

	redirect(network::getNetworkAccess('external') . '/index.php?v=d&p=gCalendar&m=gCalendar&id=' . $eqLogic->getId());
} catch (Exception $e) {
	exit(print_r($e));
}
