<?php

/* This file is part of Jeedom.
 *
 * Jeedom is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Jeedom is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
 */

/* * ***************************Includes********************************* */
require_once dirname(__FILE__) . '/../../../../core/php/core.inc.php';

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class gCalendar extends eqLogic {
	/*     * *************************Attributs****************************** */

	public static function pull($_option) {
		$gCalendar = self::byId($_option['gCalendar_id']);
		if (!is_object($gCalendar)) {
			return;
		}
		$event = $gCalendar->getCache('event', null);
		if ($event == null) {
			return;
		}
		if ($event['mode'] == 'start') {
			$gCalendar->checkAndUpdateCmd('event', $event['event']['summary']);
			if ($gCalendar->getConfiguration('allowInteract') == 1 && substr(trim($event['event']['summary']), 0, 1) == '#') {
				$param = array('emptyReply' => 1);
				$response = interactQuery::tryToReply($event['event']['summary'], $param);
				if ($response != '' && $gCalendar->getConfiguration('redirectJeedomResponse') != '') {
					$cmd = cmd::byId(str_replace('#', '', $gCalendar->getConfiguration('redirectJeedomResponse')));
					if (!is_object($cmd)) {
						throw new Exception(__('Commande de réponse introuvable :', __FILE__) . ' ' . $gCalendar->getConfiguration('redirectJeedomResponse'));
					}
					$cmd->execCmd(array('message' => $response));
				}
			}
		} else {
			$gCalendar->checkAndUpdateCmd('event', '');
		}
		$gCalendar->syncWithGoogle();
		$gCalendar->reschedule();
	}

	public static function cron30() {
		foreach (self::byType('gCalendar') as $eqLogic) {
			try {
				$eqLogic->syncWithGoogle();
				$eqLogic->reschedule();
			} catch (Exception $e) {
				log::add('gCalendar', 'error', __('Erreur sur : ', __FILE__) . $eqLogic->getHumanName() . ' => ' . $e->getMessage());
			}
		}
	}

	/*     * ***********************Methode static*************************** */

	public function getProvider() {
		return new googleProvider([
			'clientId' => $this->getConfiguration('client_id'),
			'clientSecret' => $this->getConfiguration('client_secret'),
			'redirectUri' => network::getNetworkAccess('external') . '/plugins/gCalendar/core/php/callback.php?apikey=' . config::byKey('api') . '&eqLogic_id=' . $this->getId(),
			'accessType' => 'offline',
		]);
	}

	public function getAccessToken() {
		$provider = $this->getProvider();
		$existingAccessToken = new AccessToken($this->getConfiguration('accessToken'));
		if ($existingAccessToken->hasExpired()) {
			$newAccessToken = $provider->getAccessToken('refresh_token', [
				'refresh_token' => $existingAccessToken->getRefreshToken(),
			]);
			$this->setConfiguration('accessToken', $newAccessToken->jsonSerialize());
			$this->save();
			return $newAccessToken;
		}
		return $existingAccessToken;
	}

	public function linkToUser() {
		@session_start();
		$provider = $this->getProvider();
		$authorizationUrl = $provider->getAuthorizationUrl();
		$_SESSION['oauth2state'] = $provider->getState();
		return $authorizationUrl;
	}

	public function request($_type, $_request, $_options = array()) {
		$options = array();
		$options = array_merge_recursive($options, $_options);
		$provider = $this->getProvider();
		$request = $provider->getAuthenticatedRequest($_type, 'https://www.googleapis.com/calendar/v3/' . trim($_request, '/'), $this->getAccessToken(), $options);
		return $provider->getResponse($request);
	}

	public function listCalendar() {
		$result = $this->request('GET', '/users/me/calendarList');
		return (isset($result['items'])) ? $result['items'] : array();
	}

	public function getEvents($_calendarId) {
		$result = $this->request('GET', '/calendars/' . $_calendarId . '/events?timeMin=' . urlencode(date(DATE_RFC3339)) . '&timeMax=' . urlencode(date(DATE_RFC3339, strtotime('+1 week'))));

		return (isset($result['items'])) ? $result['items'] : array();
	}

	public function syncWithGoogle() {
		$events = array();
		foreach ($this->getConfiguration('calendars') as $calendarId => $value) {
			if ($value == 0) {
				continue;
			}
			try {
				foreach ($this->getEvents($calendarId) as $event) {
					$events[] = array(
						'summary' => $event['summary'],
						'start' => (isset($event['start']['date'])) ? $event['start']['date'] : date('Y-m-d H:i:s', strtotime($event['start']['dateTime'])),
						'end' => (isset($event['end']['date'])) ? $event['end']['date'] : date('Y-m-d H:i:s', strtotime($event['end']['dateTime'])),
					);
				}
			} catch (Exception $e) {
				log::add('gCalendar', 'error', __('Erreur sur : ', __FILE__) . $calendarId . ' => ' . $e->getMessage());
			}
		}
		if (count($events) > 0) {
			$this->setCache('events', $events);
		}
	}

	public function getNextOccurence() {
		$return = array('datetime' => null, 'event' => null, 'mode' => null);
		foreach ($this->getCache('events') as $event) {
			if ($return['event'] == null) {
				$return['event'] = $event;
				if (strtotime($event['start']) > strtotime('now')) {
					$return['mode'] = 'start';
					$return['datetime'] = $event['start'];
				} else if (strtotime($event['end']) > strtotime('now')) {
					$return['mode'] = 'end';
					$return['datetime'] = $event['end'];
				}
				continue;
			}
			if (strtotime($event['start']) > strtotime('now') && ($return['datetime'] == null || strtotime($event['start']) < strtotime($return['datetime']))) {
				$return['mode'] = 'start';
				$return['datetime'] = $event['start'];
				$return['event'] = $event;
			}
			if (strtotime($event['end']) > strtotime('now') && ($return['datetime'] == null || strtotime($event['end']) < strtotime($return['datetime']))) {
				$return['mode'] = 'end';
				$return['datetime'] = $event['end'];
				$return['event'] = $event;
			}
		}
		return $return;
	}

	public function reschedule() {
		$next = $this->getNextOccurence();
		if ($next['datetime'] === null || $next['datetime'] === false) {
			return;
		}
		log::add('gCalendar', 'debug', 'Reprogrammation à : ' . print_r($next['datetime'], true));
		$cron = cron::byClassAndFunction('gCalendar', 'pull', array('gCalendar_id' => intval($this->getId())));
		if ($next['datetime'] != null) {
			if (!is_object($cron)) {
				$cron = new cron();
				$cron->setClass('gCalendar');
				$cron->setFunction('pull');
				$cron->setOption(array('gCalendar_id' => intval($this->getId())));
				$cron->setLastRun(date('Y-m-d H:i:s'));
			}
			$next['datetime'] = strtotime($next['datetime']);
			$cron->setSchedule(date('i', $next['datetime']) . ' ' . date('H', $next['datetime']) . ' ' . date('d', $next['datetime']) . ' ' . date('m', $next['datetime']) . ' * ' . date('Y', $next['datetime']));
			$cron->save();
			$this->setCache('event', $next);
		} else {
			if (is_object($cron)) {
				$cron->remove();
			}
		}
	}

	public function preSave() {
		$cmd = $this->getCmd(null, 'event');
		if (!is_object($cmd)) {
			$cmd = new gCalendarCmd();
			$cmd->setLogicalId('event');
			$cmd->setIsVisible(1);
			$cmd->setOrder(4);
			$cmd->setName(__('Evènement', __FILE__));
			$cmd->setTemplate('dashboard', 'line');
			$cmd->setTemplate('mobile', 'line');
		}
		$cmd->setType('info');
		$cmd->setSubType('string');
		$cmd->setEqLogic_id($this->getId());
		$cmd->save();
	}

	/*     * *********************Methode d'instance************************* */
}

class gCalendarCmd extends cmd {
	/*     * *************************Attributs****************************** */

	/*     * ***********************Methode static*************************** */

	/*     * *********************Methode d'instance************************* */

	public function execute($_options = array()) {

	}

	/*     * **********************Getteur Setteur*************************** */

}

class googleProvider extends AbstractProvider {
	use BearerAuthorizationTrait;
	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'id';
	protected $accessType;
	protected $hostedDomain;
	protected $defaultUserFields = [
		'id',
		'name(familyName,givenName)',
		'displayName',
		'emails/value',
		'image/url',
	];
	protected $userFields = [];

	public function getBaseAuthorizationUrl() {
		return 'https://accounts.google.com/o/oauth2/auth';
	}

	public function getBaseAccessTokenUrl(array $params) {
		return 'https://accounts.google.com/o/oauth2/token';
	}

	public function getResourceOwnerDetailsUrl(AccessToken $token) {
		$fields = array_merge($this->defaultUserFields, $this->userFields);
		return 'https://www.googleapis.com/plus/v1/people/me?' . http_build_query([
			'fields' => implode(',', $fields),
			'alt' => 'json',
		]);
	}

	protected function getAuthorizationParameters(array $options) {
		$params = array_merge(
			parent::getAuthorizationParameters($options),
			array_filter([
				'hd' => $this->hostedDomain,
				'access_type' => $this->accessType,
				'authuser' => '-1',
			])
		);
		return $params;
	}

	protected function getDefaultScopes() {
		return [
			'email',
			'openid',
			'profile',
			'https://www.googleapis.com/auth/calendar.readonly',
		];
	}

	protected function getScopeSeparator() {
		return ' ';
	}

	protected function checkResponse(ResponseInterface $response, $data) {
		if (!empty($data['error'])) {
			$code = 0;
			$error = $data['error'];
			if (is_array($error)) {
				$code = $error['code'];
				$error = $error['message'];
			}
			throw new IdentityProviderException($error, $code, $data);
		}
	}

	protected function createResourceOwner(array $response, AccessToken $token) {
		return new googleOwner($response);
	}
}

class googleOwner implements ResourceOwnerInterface {
	protected $response;

	public function __construct(array $response) {
		$this->response = $response;
	}
	public function getId() {
		return $this->response['id'];
	}

	public function getName() {
		return $this->response['displayName'];
	}

	public function getFirstName() {
		return $this->response['name']['givenName'];
	}

	public function getLastName() {
		return $this->response['name']['familyName'];
	}

	public function getEmail() {
		if (!empty($this->response['emails'])) {
			return $this->response['emails'][0]['value'];
		}
	}

	public function getAvatar() {
		if (!empty($this->response['image']['url'])) {
			return $this->response['image']['url'];
		}
	}

	public function toArray() {
		return $this->response;
	}
}