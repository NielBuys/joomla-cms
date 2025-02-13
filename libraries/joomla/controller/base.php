<?php
/**
 * @package     Joomla.Platform
 * @subpackage  Controller
 *
 * @copyright   (C) 2012 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('JPATH_PLATFORM') or die;

use Joomla\Application\AbstractApplication;

/**
 * Joomla Platform Base Controller Class
 *
 * @since       3.0.0
 * @deprecated  4.0 Use the default MVC library
 */
abstract class JControllerBase implements JController
{
	/**
	 * The application object.
	 *
	 * @var    AbstractApplication
	 * @since  3.0.0
	 */
	protected $app;

	/**
	 * The input object.
	 *
	 * @var    JInput
	 * @since  3.0.0
	 */
	protected $input;

	/**
	 * Instantiate the controller.
	 *
	 * @param   JInput               $input  The input object.
	 * @param   AbstractApplication  $app    The application object.
	 *
	 * @since  3.0.0
	 */
	public function __construct(?JInput $input = null, ?AbstractApplication $app = null)
	{
		// Setup dependencies.
		$this->app = isset($app) ? $app : $this->loadApplication();
		$this->input = isset($input) ? $input : $this->loadInput();
	}

	/**
	 * Get the application object.
	 *
	 * @return  AbstractApplication  The application object.
	 *
	 * @since   3.0.0
	 */
	public function getApplication()
	{
		return $this->app;
	}

	/**
	 * Get the input object.
	 *
	 * @return  JInput  The input object.
	 *
	 * @since   3.0.0
	 */
	public function getInput()
	{
		return $this->input;
	}

	/**
	 * Serialize the controller.
	 *
	 * @return  string  The serialized controller.
	 *
	 * @since   3.0.0
	 */
	public function serialize()
	{
		return serialize($this->input);
	}
	public function __serialize()
	{
		return serialize($this->input);
	}

	/**
	 * Unserialize the controller.
	 *
	 * @param   string  $input  The serialized controller.
	 *
	 * @return  JController  Supports chaining.
	 *
	 * @since   3.0.0
	 * @throws  UnexpectedValueException if input is not the right class.
	 */
	public function unserialize($input)
	{
		// Setup dependencies.
		$this->app = $this->loadApplication();

		// Unserialize the input.
		$this->input = unserialize($input);

		if (!($this->input instanceof JInput))
		{
			throw new UnexpectedValueException(sprintf('%s::unserialize would not accept a `%s`.', get_class($this), gettype($this->input)));
		}

		return $this;
	}
	public function __unserialize($input)
	{
		// Setup dependencies.
		$this->app = $this->loadApplication();

		// Unserialize the input.
		$this->input = unserialize($input);

		if (!($this->input instanceof JInput))
		{
			throw new UnexpectedValueException(sprintf('%s::unserialize would not accept a `%s`.', get_class($this), gettype($this->input)));
		}

		return $this;
	}

	/**
	 * Load the application object.
	 *
	 * @return  AbstractApplication  The application object.
	 *
	 * @since   3.0.0
	 */
	protected function loadApplication()
	{
		return JFactory::getApplication();
	}

	/**
	 * Load the input object.
	 *
	 * @return  JInput  The input object.
	 *
	 * @since   3.0.0
	 */
	protected function loadInput()
	{
		return $this->app->input;
	}
}
