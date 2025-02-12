<?php
/**
 * @package     Joomla.Administrator
 * @subpackage  com_media
 *
 * @copyright   (C) 2005 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

$input  = JFactory::getApplication()->input;
$user   = JFactory::getUser();
$asset  = $input->get('asset');
$author = $input->get('author');

// Access check.
if (!$user->authorise('core.manage', 'com_media') && (!$asset || (!$user->authorise('core.edit', $asset)
	&& !$user->authorise('core.create', $asset)
	&& count($user->getAuthorisedCategories($asset, 'core.create')) == 0)
	&& !($user->id == $author && $user->authorise('core.edit.own', $asset))))
{
	throw new JAccessExceptionNotallowed(JText::_('JERROR_ALERTNOAUTHOR'), 403);
}

$params = JComponentHelper::getParams('com_media');

// Load the helper class
JLoader::register('MediaHelper', JPATH_ADMINISTRATOR . '/components/com_media/helpers/media.php');

// Set the path definitions
$popup_upload = $input->get('pop_up', null);
$path         = 'file_path';
$view         = $input->get('view');

if (substr(strtolower($view ?? ''), 0, 6) == 'images' || $popup_upload == 1)
{
	$path = 'image_path';
}

$mediaBaseDir = JPATH_ROOT . '/' . $params->get($path, 'images');

if (!is_dir($mediaBaseDir))
{
	throw new \InvalidArgumentException(JText::_('JERROR_AN_ERROR_HAS_OCCURRED'), 500);
}

define('COM_MEDIA_BASE', $mediaBaseDir);
define('COM_MEDIA_BASEURL', JUri::root() . $params->get($path, 'images'));

$controller = JControllerLegacy::getInstance('Media', array('base_path' => JPATH_COMPONENT_ADMINISTRATOR));
$controller->execute($input->get('task'));
$controller->redirect();
