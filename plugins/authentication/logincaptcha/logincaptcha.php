<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.logincaptcha
 *
 * @copyright   (C) 2018 Niel Buys. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Login CAPTCHA authentication plugin.
 *
 * Behaves like the core "Authentication - Joomla" plugin (username/password + two factor),
 * but first requires the visitor to pass the site's configured CAPTCHA. This blocks
 * automated/bot login attempts.
 *
 * Purpose:
 *   1. Show a CAPTCHA on the login form to stop bots trying to log in.
 *   2. After a successful login the visitor is issued a signed "captcha passed" cookie so
 *      they do not have to solve the CAPTCHA on every login (optional, see the "Enable
 *      Cookie" parameter).
 *   3. The CAPTCHA is rendered wherever a login form calls the "showcaptcha" event
 *      (front-end login module, com_users login view, and the administrator login).
 *   4. The "captcha passed" cookie carries a signed expiry (default ~3 months) which is
 *      enforced server-side, so the CAPTCHA is required again once it lapses.
 *
 * IMPORTANT: This plugin fully replaces the core "Authentication - Joomla" plugin. For the
 * CAPTCHA to actually be enforced the core "Authentication - Joomla" plugin MUST be
 * DISABLED, otherwise it will authenticate the same credentials without the CAPTCHA and the
 * gate is bypassed. This plugin warns the administrator when it detects that situation.
 *
 * @since  1.0
 */
class PlgAuthenticationLogincaptcha extends JPlugin
{
	/**
	 * Load the language file on instantiation.
	 *
	 * @var    boolean
	 * @since  1.0
	 */
	protected $autoloadLanguage = true;

	/**
	 * Name of the "captcha passed" cookie.
	 *
	 * @var    string
	 * @since  1.1
	 */
	const COOKIE_NAME = 'plg_logincaptcha';

	/**
	 * The constant payload that is signed to build the "captcha passed" token.
	 *
	 * @var    string
	 * @since  1.1
	 */
	const TOKEN_LABEL = 'captcha-ok';

	/**
	 * This method handles authentication and reports back to the subject.
	 *
	 * @param   array   $credentials  Array holding the user credentials.
	 * @param   array   $options      Array of extra options.
	 * @param   object  &$response    Authentication response object.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		$response->type = 'Joomla';

		// Joomla does not like blank passwords.
		if (empty($credentials['password']))
		{
			$response->status        = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return;
		}

		$app = JFactory::getApplication();

		// Warn if the core Joomla authentication plugin is also enabled: it would bypass this CAPTCHA.
		$this->warnIfCoreJoomlaPluginEnabled($app);

		// Determine whether the CAPTCHA still needs to be solved on this request.
		$captchaRequired = JPluginHelper::isEnabled('captcha') && !$this->hasValidCaptchaToken($app);

		if ($captchaRequired && !$this->passesCaptcha($app, $response))
		{
			// $response has already been populated with the failure by passesCaptcha().
			return;
		}

		// Get a database object.
		$db    = JFactory::getDbo();
		$query = $db->getQuery(true)
			->select('id, password')
			->from('#__users')
			->where('username=' . $db->quote($credentials['username']));

		$db->setQuery($query);
		$result = $db->loadObject();

		if ($result)
		{
			$match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);

			if ($match === true)
			{
				// Bring this in line with the rest of the system.
				$user               = JUser::getInstance($result->id);
				$response->email    = $user->email;
				$response->fullname = $user->name;

				if ($app->isClient('administrator'))
				{
					$response->language = $user->getParam('admin_language');
				}
				else
				{
					$response->language = $user->getParam('language');
				}

				$response->status        = JAuthentication::STATUS_SUCCESS;
				$response->error_message = '';

				// Issue the "captcha passed" cookie so the user can skip the CAPTCHA next time.
				if ($captchaRequired)
				{
					$this->issueCaptchaToken($app);
				}
			}
			else
			{
				// Invalid password.
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			// Let's hash the entered password even if we don't have a matching user for some extra response time.
			// By doing so, we mitigate side channel user enumeration attacks.
			JUserHelper::hashPassword($credentials['password']);

			// Invalid user.
			$response->status        = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
		}

		// Check the two factor authentication.
		if ($response->status === JAuthentication::STATUS_SUCCESS)
		{
			$methods = JAuthenticationHelper::getTwoFactorMethods();

			if (count($methods) <= 1)
			{
				// No two factor authentication method is enabled.
				return;
			}

			JModelLegacy::addIncludePath(JPATH_ADMINISTRATOR . '/components/com_users/models', 'UsersModel');

			/** @var UsersModelUser $model */
			$model = JModelLegacy::getInstance('User', 'UsersModel', array('ignore_request' => true));

			// Load the user's OTP (one time password, a.k.a. two factor auth) configuration.
			if (!array_key_exists('otp_config', $options))
			{
				$otpConfig             = $model->getOtpConfig($result->id);
				$options['otp_config'] = $otpConfig;
			}
			else
			{
				$otpConfig = $options['otp_config'];
			}

			// Check if the user has enabled two factor authentication.
			if (empty($otpConfig->method) || ($otpConfig->method === 'none'))
			{
				// Warn the user if they are using a secret code but they have not
				// enabled two factor auth in their account.
				if (!empty($credentials['secretkey']))
				{
					try
					{
						$this->loadLanguage();

						$app->enqueueMessage(JText::_('PLG_AUTH_JOOMLA_ERR_SECRET_CODE_WITHOUT_TFA'), 'warning');
					}
					catch (Exception $exc)
					{
						// This happens when we are in CLI mode. In this case no warning is issued.
						return;
					}
				}

				return;
			}

			// Try to validate the OTP.
			FOFPlatform::getInstance()->importPlugin('twofactorauth');

			$otpAuthReplies = FOFPlatform::getInstance()->runPlugins('onUserTwofactorAuthenticate', array($credentials, $options));

			$check = false;

			/*
			 * This looks like noob code but DO NOT TOUCH IT and do not convert
			 * to in_array(). During testing in_array() inexplicably returned
			 * null when the OTEP begins with a zero! o_O
			 */
			if (!empty($otpAuthReplies))
			{
				foreach ($otpAuthReplies as $authReply)
				{
					$check = $check || $authReply;
				}
			}

			// Fall back to one time emergency passwords.
			if (!$check)
			{
				// Did the user use an OTEP instead?
				if (empty($otpConfig->otep))
				{
					if (empty($otpConfig->method) || ($otpConfig->method === 'none'))
					{
						// Two factor authentication is not enabled on this account.
						// Any string is assumed to be a valid OTEP.
						return;
					}
					else
					{
						/*
						 * Two factor authentication enabled and no OTEPs defined. The
						 * user has used them all up. Therefore anything they enter is
						 * an invalid OTEP.
						 */
						$response->status        = JAuthentication::STATUS_FAILURE;
						$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');

						return;
					}
				}

				// Clean up the OTEP (remove dashes, spaces and other funny stuff
				// our beloved users may have unwittingly stuffed in it).
				$otep  = $credentials['secretkey'];
				$otep  = filter_var($otep, FILTER_SANITIZE_NUMBER_INT);
				$otep  = str_replace('-', '', $otep);
				$check = false;

				// Did we find a valid OTEP?
				if (in_array($otep, $otpConfig->otep))
				{
					// Remove the OTEP from the array.
					$otpConfig->otep = array_diff($otpConfig->otep, array($otep));

					$model->setOtpConfig($result->id, $otpConfig);

					// Return true; the OTEP was a valid one.
					$check = true;
				}
			}

			if (!$check)
			{
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');
			}
		}
	}

	/**
	 * Renders the CAPTCHA for the login form.
	 *
	 * Called from the login templates via the custom "showcaptcha" event. The first element
	 * of the returned array is the HTML to output (empty string when nothing should show).
	 *
	 * @return  array  Array whose element [0] is the CAPTCHA HTML (or an empty string).
	 *
	 * @since   1.0
	 */
	public function showcaptcha()
	{
		$app = JFactory::getApplication();

		// Warn administrators about the bypass risk when the core Joomla plugin is also enabled.
		$this->warnIfCoreJoomlaPluginEnabled($app);

		// Nothing to render if no CAPTCHA plugin is enabled. Nag administrators only; never
		// surface configuration details on the public front-end login.
		if (!JPluginHelper::isEnabled('captcha'))
		{
			if ($app->isClient('administrator'))
			{
				return array('<div class="alert alert-warning">' . JText::_('PLG_LOGINCAPTCHA_CAPTCHA_NOTENABLED') . '</div>');
			}

			return array('');
		}

		// If the visitor already holds a valid "captcha passed" token there is nothing to show.
		if ($this->hasValidCaptchaToken($app))
		{
			return array('');
		}

		// Load and trigger CAPTCHA display.
		JPluginHelper::importPlugin('captcha');
		$dispatcher = JEventDispatcher::getInstance();
		$dispatcher->trigger('onInit', 'dynamic_recaptcha_1');
		$recaptcha = $dispatcher->trigger('onDisplay', array(null, 'dynamic_recaptcha_1', ''));

		return $recaptcha;
	}

	/**
	 * Validates the submitted CAPTCHA answer.
	 *
	 * On failure it populates $response and returns false.
	 *
	 * @param   JApplicationCms  $app       The application.
	 * @param   object           &$response  Authentication response object.
	 *
	 * @return  boolean  True when the CAPTCHA passes.
	 *
	 * @since   1.1
	 */
	protected function passesCaptcha($app, &$response)
	{
		$post = $app->input->post->getArray();

		JPluginHelper::importPlugin('captcha');

		try
		{
			$results = JEventDispatcher::getInstance()->trigger('onCheckAnswer', array($post));

			$passed = false;

			foreach ($results as $result)
			{
				if ($result === true)
				{
					$passed = true;
					break;
				}
			}

			if (!$passed)
			{
				throw new RuntimeException('CAPTCHA verification failed');
			}
		}
		catch (Exception $e)
		{
			$response->status        = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('PLG_LOGINCAPTCHA_CAPTCHA_FAILED');

			if (JFactory::getConfig()->get('debug'))
			{
				$app->enqueueMessage($e->getMessage(), 'warning');
			}
			else
			{
				$app->enqueueMessage(JText::_('PLG_LOGINCAPTCHA_CAPTCHA_FAILED'), 'warning');
			}

			return false;
		}

		return true;
	}

	/**
	 * Whether the "skip CAPTCHA after a successful login" cookie feature is enabled.
	 *
	 * @return  boolean
	 *
	 * @since   1.1
	 */
	protected function cookieFeatureEnabled()
	{
		return (int) $this->params->get('DisableCaptchaSetCookie', 0) === 1;
	}

	/**
	 * The lifetime, in seconds, of the "captcha passed" cookie (default ~3 months).
	 *
	 * @return  integer
	 *
	 * @since   1.1
	 */
	protected function cookieLifetime()
	{
		$lifetime = (int) $this->params->get('CookieTime', 7889238);

		// Guard against a zero/negative configuration which would issue an already-expired token.
		return $lifetime > 0 ? $lifetime : 7889238;
	}

	/**
	 * Builds the HMAC signature for a "captcha passed" token with the given expiry.
	 *
	 * The signed payload includes the expiry and a short hash of the user agent, so the token
	 * cannot be replayed after it lapses and is bound to the browser it was issued for. The
	 * key is the site secret, so the token cannot be forged without it.
	 *
	 * @param   integer  $expiry  Unix timestamp when the token expires.
	 *
	 * @return  string  Hex HMAC signature.
	 *
	 * @since   1.1
	 */
	protected function signCaptchaToken($expiry)
	{
		$secret = (string) JFactory::getConfig()->get('secret');
		$ua     = JUserHelper::getShortHashedUserAgent();

		return hash_hmac('sha256', self::TOKEN_LABEL . '|' . $expiry . '|' . $ua, $secret);
	}

	/**
	 * Checks whether the request carries a valid, unexpired "captcha passed" token.
	 *
	 * @param   JApplicationCms  $app  The application.
	 *
	 * @return  boolean
	 *
	 * @since   1.1
	 */
	protected function hasValidCaptchaToken($app)
	{
		if (!$this->cookieFeatureEnabled())
		{
			return false;
		}

		$cookie = (string) $app->input->cookie->get(self::COOKIE_NAME, '', 'raw');

		if ($cookie === '')
		{
			return false;
		}

		$decoded = base64_decode($cookie, true);

		if ($decoded === false || strpos($decoded, '.') === false)
		{
			return false;
		}

		list($expiry, $signature) = explode('.', $decoded, 2);

		// Expiry must be a plain integer and still in the future (server-side enforcement).
		if (!ctype_digit($expiry) || (int) $expiry < time())
		{
			return false;
		}

		return hash_equals($this->signCaptchaToken($expiry), $signature);
	}

	/**
	 * Issues a fresh, signed "captcha passed" cookie.
	 *
	 * @param   JApplicationCms  $app  The application.
	 *
	 * @return  void
	 *
	 * @since   1.1
	 */
	protected function issueCaptchaToken($app)
	{
		if (!$this->cookieFeatureEnabled())
		{
			return;
		}

		$expiry = time() + $this->cookieLifetime();
		$value  = base64_encode($expiry . '.' . $this->signCaptchaToken($expiry));

		$app->input->cookie->set(
			self::COOKIE_NAME,
			$value,
			$expiry,
			$app->get('cookie_path', '/'),
			$app->get('cookie_domain', ''),
			$app->isHttpsForced() || $app->isSSLConnection(),
			true
		);
	}

	/**
	 * Logs (and, in the administrator, shows) a warning when the core "Authentication - Joomla"
	 * plugin is also enabled, which would let logins bypass this CAPTCHA.
	 *
	 * @param   JApplicationCms  $app  The application.
	 *
	 * @return  void
	 *
	 * @since   1.1
	 */
	protected function warnIfCoreJoomlaPluginEnabled($app)
	{
		if (!JPluginHelper::isEnabled('authentication', 'joomla'))
		{
			return;
		}

		JLog::add(
			'plg_authentication_logincaptcha: the core "Authentication - Joomla" plugin is enabled and will bypass the login CAPTCHA. Disable it.',
			JLog::WARNING,
			'security'
		);

		// Only surface this to administrators to avoid leaking configuration details to the public.
		if ($app->isClient('administrator'))
		{
			try
			{
				$app->enqueueMessage(JText::_('PLG_LOGINCAPTCHA_WARN_CORE_JOOMLA_ENABLED'), 'warning');
			}
			catch (Exception $e)
			{
				// No application (CLI); nothing to enqueue.
			}
		}
	}
}
