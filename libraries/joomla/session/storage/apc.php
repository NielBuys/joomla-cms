<?php
/**
 * @package     Joomla.Platform
 * @subpackage  Session
 *
 * @copyright   (C) 2007 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('JPATH_PLATFORM') or die;

/**
 * APC session storage handler for PHP
 *
 * @link        https://www.php.net/manual/en/function.session-set-save-handler.php
 * @since       1.7.0
 * @deprecated  4.0  The CMS' Session classes will be replaced with the `joomla/session` package
 */
class JSessionStorageApc extends JSessionStorage
{
	/**
	 * Constructor
	 *
	 * @param   array  $options  Optional parameters
	 *
	 * @since   1.7.0
	 * @throws  RuntimeException
	 */
	public function __construct($options = array())
	{
		if (!self::isSupported())
		{
			throw new RuntimeException('APC Extension is not available', 404);
		}

		parent::__construct($options);
	}

	/**
	 * Read the data for a particular session identifier from the
	 * SessionHandler backend.
	 *
	 * @param   string  $id  The session identifier.
	 *
	 * @return  string  The session data.
	 *
	 * @since   1.7.0
	 */
	public function read(string $id): string|false
	{
		$sess_id = 'sess_' . $id;

		return (string) apc_fetch($sess_id);
	}

	/**
	 * Write session data to the SessionHandler backend.
	 *
	 * @param   string  $id           The session identifier.
	 * @param   string  $sessionData  The session data.
	 *
	 * @return  boolean  True on success, false otherwise.
	 *
	 * @since   1.7.0
	 */
	public function write($id, $sessionData): bool
	{
		$sess_id = 'sess_' . $id;

		return apc_store($sess_id, $sessionData, ini_get('session.gc_maxlifetime'));
	}

	/**
	 * Destroy the data for a particular session identifier in the SessionHandler backend.
	 *
	 * @param   string  $id  The session identifier.
	 *
	 * @return  boolean  True on success, false otherwise.
	 *
	 * @since   1.7.0
	 */
	public function destroy($id): bool
	{
		$sess_id = 'sess_' . $id;

		return apc_delete($sess_id);
	}

	/**
	 * Test to see if the SessionHandler is available.
	 *
	 * @return boolean  True on success, false otherwise.
	 *
	 * @since   3.0.0
	 */
	public static function isSupported()
	{
		return extension_loaded('apc');
	}
}
