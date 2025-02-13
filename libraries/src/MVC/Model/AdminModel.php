<?php
/**
 * Joomla! Content Management System
 *
 * @copyright  (C) 2010 Open Source Matters, Inc. <https://www.joomla.org>
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Joomla\CMS\MVC\Model;

defined('JPATH_PLATFORM') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\LanguageHelper;
use Joomla\CMS\MVC\Factory\MVCFactoryInterface;
use Joomla\Registry\Registry;
use Joomla\String\StringHelper;
use Joomla\Utilities\ArrayHelper;

/**
 * Prototype admin model.
 *
 * @since  1.6
 */
abstract class AdminModel extends FormModel
{
	/**
	 * The type alias for this content type (for example, 'com_content.article').
	 *
	 * @var    string
	 * @since  3.8.6
	 */
	public $typeAlias;

	/**
	 * The prefix to use with controller messages.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $text_prefix = null;

	/**
	 * The event to trigger after deleting the data.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $event_after_delete = null;

	/**
	 * The event to trigger after saving the data.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $event_after_save = null;

	/**
	 * The event to trigger before deleting the data.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $event_before_delete = null;

	/**
	 * The event to trigger before saving the data.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $event_before_save = null;

	/**
	 * The event to trigger after changing the published state of the data.
	 *
	 * @var    string
	 * @since  1.6
	 */
	protected $event_change_state = null;

	/**
	 * Batch copy/move command. If set to false,
	 * the batch copy/move command is not supported
	 *
	 * @var    string
	 * @since  3.4
	 */
	protected $batch_copymove = 'category_id';

	/**
	 * Allowed batch commands
	 *
	 * @var    array
	 * @since  3.4
	 */
	protected $batch_commands = array(
		'assetgroup_id' => 'batchAccess',
		'language_id' => 'batchLanguage',
		'tag' => 'batchTag',
	);

	/**
	 * The context used for the associations table
	 *
	 * @var     string
	 * @since   3.4.4
	 */
	protected $associationsContext = null;

	/**
	 * A flag to indicate if member variables for batch actions (and saveorder) have been initialized
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $batchSet = null;

	/**
	 * The user performing the actions (re-usable in batch methods & saveorder(), initialized via initBatch())
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $user = null;

	/**
	 * A JTable instance (of appropriate type) to manage the DB records (re-usable in batch methods & saveorder(), initialized via initBatch())
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $table = null;

	/**
	 * The class name of the JTable instance managing the DB records (re-usable in batch methods & saveorder(), initialized via initBatch())
	 *
	 * @var     string
	 * @since   3.8.2
	 */
	protected $tableClassName = null;

	/**
	 * UCM Type corresponding to the current model class (re-usable in batch action methods, initialized via initBatch())
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $contentType = null;

	/**
	 * DB data of UCM Type corresponding to the current model class (re-usable in batch action methods, initialized via initBatch())
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $type = null;

	/**
	 * A tags Observer instance to handle assigned tags (re-usable in batch action methods, initialized via initBatch())
	 *
	 * @var     object
	 * @since   3.8.2
	 */
	protected $tagsObserver = null;


	/**
	 * Constructor.
	 *
	 * @param   array                $config   An optional associative array of configuration settings.
	 * @param   MVCFactoryInterface  $factory  The factory.
	 *
	 * @see     \JModelLegacy
	 * @since   1.6
	 */
	public function __construct($config = array(), ?MVCFactoryInterface $factory = null)
	{
		parent::__construct($config, $factory);

		if (isset($config['event_after_delete']))
		{
			$this->event_after_delete = $config['event_after_delete'];
		}
		elseif (empty($this->event_after_delete))
		{
			$this->event_after_delete = 'onContentAfterDelete';
		}

		if (isset($config['event_after_save']))
		{
			$this->event_after_save = $config['event_after_save'];
		}
		elseif (empty($this->event_after_save))
		{
			$this->event_after_save = 'onContentAfterSave';
		}

		if (isset($config['event_before_delete']))
		{
			$this->event_before_delete = $config['event_before_delete'];
		}
		elseif (empty($this->event_before_delete))
		{
			$this->event_before_delete = 'onContentBeforeDelete';
		}

		if (isset($config['event_before_save']))
		{
			$this->event_before_save = $config['event_before_save'];
		}
		elseif (empty($this->event_before_save))
		{
			$this->event_before_save = 'onContentBeforeSave';
		}

		if (isset($config['event_change_state']))
		{
			$this->event_change_state = $config['event_change_state'];
		}
		elseif (empty($this->event_change_state))
		{
			$this->event_change_state = 'onContentChangeState';
		}

		$config['events_map'] = isset($config['events_map']) ? $config['events_map'] : array();

		$this->events_map = array_merge(
			array(
				'delete'       => 'content',
				'save'         => 'content',
				'change_state' => 'content',
				'validate'     => 'content',
			), $config['events_map']
		);

		// Guess the \JText message prefix. Defaults to the option.
		if (isset($config['text_prefix']))
		{
			$this->text_prefix = strtoupper($config['text_prefix']);
		}
		elseif (empty($this->text_prefix))
		{
			$this->text_prefix = strtoupper($this->option);
		}
	}

	/**
	 * Method to perform batch operations on an item or a set of items.
	 *
	 * @param   array  $commands  An array of commands to perform.
	 * @param   array  $pks       An array of item ids.
	 * @param   array  $contexts  An array of item contexts.
	 *
	 * @return  boolean  Returns true on success, false on failure.
	 *
	 * @since   1.7
	 */
	public function batch($commands, $pks, $contexts)
	{
		// Sanitize ids.
		$pks = array_unique($pks);
		$pks = ArrayHelper::toInteger($pks);

		// Remove any values of zero.
		if (array_search(0, $pks, true))
		{
			unset($pks[array_search(0, $pks, true)]);
		}

		if (empty($pks))
		{
			$this->setError(\JText::_('JGLOBAL_NO_ITEM_SELECTED'));

			return false;
		}

		$done = false;

		// Initialize re-usable member properties
		$this->initBatch();

		if ($this->batch_copymove && !empty($commands[$this->batch_copymove]))
		{
			$cmd = ArrayHelper::getValue($commands, 'move_copy', 'c');

			if ($cmd === 'c')
			{
				$result = $this->batchCopy($commands[$this->batch_copymove], $pks, $contexts);

				if (is_array($result))
				{
					foreach ($result as $old => $new)
					{
						$contexts[$new] = $contexts[$old];
					}

					$pks = array_values($result);
				}
				else
				{
					return false;
				}
			}
			elseif ($cmd === 'm' && !$this->batchMove($commands[$this->batch_copymove], $pks, $contexts))
			{
				return false;
			}

			$done = true;
		}

		foreach ($this->batch_commands as $identifier => $command)
		{
			if (!empty($commands[$identifier]))
			{
				if (!$this->$command($commands[$identifier], $pks, $contexts))
				{
					return false;
				}

				$done = true;
			}
		}

		if (!$done)
		{
			$this->setError(\JText::_('JLIB_APPLICATION_ERROR_INSUFFICIENT_BATCH_INFORMATION'));

			return false;
		}

		// Clear the cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Batch access level changes for a group of rows.
	 *
	 * @param   integer  $value     The new value matching an Asset Group ID.
	 * @param   array    $pks       An array of row IDs.
	 * @param   array    $contexts  An array of item contexts.
	 *
	 * @return  boolean  True if successful, false otherwise and internal error is set.
	 *
	 * @since   1.7
	 */
	protected function batchAccess($value, $pks, $contexts)
	{
		// Initialize re-usable member properties, and re-usable local variables
		$this->initBatch();

		foreach ($pks as $pk)
		{
			if ($this->user->authorise('core.edit', $contexts[$pk]))
			{
				$this->table->reset();
				$this->table->load($pk);
				$this->table->access = (int) $value;

				if (!empty($this->type))
				{
					$this->createTagsHelper($this->tagsObserver, $this->type, $pk, $this->typeAlias, $this->table);
				}

				if (!$this->table->store())
				{
					$this->setError($this->table->getError());

					return false;
				}
			}
			else
			{
				$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));

				return false;
			}
		}

		// Clean the cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Batch copy items to a new category or current.
	 *
	 * @param   integer  $value     The new category.
	 * @param   array    $pks       An array of row IDs.
	 * @param   array    $contexts  An array of item contexts.
	 *
	 * @return  array|boolean  An array of new IDs on success, boolean false on failure.
	 *
	 * @since	1.7
	 */
	protected function batchCopy($value, $pks, $contexts)
	{
		// Initialize re-usable member properties, and re-usable local variables
		$this->initBatch();

		$categoryId = $value;

		if (!$this->checkCategoryId($categoryId))
		{
			return false;
		}

		$newIds = array();
		$db     = $this->getDbo();

		// Parent exists so let's proceed
		while (!empty($pks))
		{
			// Pop the first ID off the stack
			$pk = array_shift($pks);

			$this->table->reset();

			// Check that the row actually exists
			if (!$this->table->load($pk))
			{
				if ($error = $this->table->getError())
				{
					// Fatal error
					$this->setError($error);

					return false;
				}
				else
				{
					// Not fatal error
					$this->setError(\JText::sprintf('JLIB_APPLICATION_ERROR_BATCH_MOVE_ROW_NOT_FOUND', $pk));
					continue;
				}
			}

			// Check for asset_id
			if ($this->table->hasField($this->table->getColumnAlias('asset_id')))
			{
				$oldAssetId = $this->table->asset_id;
			}

			$this->generateTitle($categoryId, $this->table);

			// Reset the ID because we are making a copy
			$this->table->id = 0;

			// Unpublish because we are making a copy
			if (isset($this->table->published))
			{
				$this->table->published = 0;
			}
			elseif (isset($this->table->state))
			{
				$this->table->state = 0;
			}

			$hitsAlias = $this->table->getColumnAlias('hits');

			if (isset($this->table->$hitsAlias))
			{
				$this->table->$hitsAlias = 0;
			}

			// New category ID
			$this->table->catid = $categoryId;

			// TODO: Deal with ordering?
			// $this->table->ordering = 1;

			// Check the row.
			if (!$this->table->check())
			{
				$this->setError($this->table->getError());

				return false;
			}

			if (!empty($this->type))
			{
				$this->createTagsHelper($this->tagsObserver, $this->type, $pk, $this->typeAlias, $this->table);
			}

			// Store the row.
			if (!$this->table->store())
			{
				$this->setError($this->table->getError());

				return false;
			}

			// Get the new item ID
			$newId = $this->table->get('id');

			if (!empty($oldAssetId))
			{
				// Copy rules
				$query = $db->getQuery(true);
				$query->clear()
					->update($db->quoteName('#__assets', 't'))
					->join('INNER', $db->quoteName('#__assets', 's') .
						' ON ' . $db->quoteName('s.id') . ' = ' . $oldAssetId
					)
					->set($db->quoteName('t.rules') . ' = ' . $db->quoteName('s.rules'))
					->where($db->quoteName('t.id') . ' = ' . $this->table->asset_id);

				$db->setQuery($query)->execute();
			}

			$this->cleanupPostBatchCopy($this->table, $newId, $pk);

			// Add the new ID to the array
			$newIds[$pk] = $newId;
		}

		// Clean the cache
		$this->cleanCache();

		return $newIds;
	}

	/**
	 * Function that can be overridden to do any data cleanup after batch copying data
	 *
	 * @param   \JTableInterface  $table  The table object containing the newly created item
	 * @param   integer           $newId  The id of the new item
	 * @param   integer           $oldId  The original item id
	 *
	 * @return  void
	 *
	 * @since  3.8.12
	 */
	protected function cleanupPostBatchCopy(\JTableInterface $table, $newId, $oldId)
	{
	}

	/**
	 * Batch language changes for a group of rows.
	 *
	 * @param   string  $value     The new value matching a language.
	 * @param   array   $pks       An array of row IDs.
	 * @param   array   $contexts  An array of item contexts.
	 *
	 * @return  boolean  True if successful, false otherwise and internal error is set.
	 *
	 * @since   2.5
	 */
	protected function batchLanguage($value, $pks, $contexts)
	{
		// Initialize re-usable member properties, and re-usable local variables
		$this->initBatch();

		foreach ($pks as $pk)
		{
			if ($this->user->authorise('core.edit', $contexts[$pk]))
			{
				$this->table->reset();
				$this->table->load($pk);
				$this->table->language = $value;

				if (!empty($this->type))
				{
					$this->createTagsHelper($this->tagsObserver, $this->type, $pk, $this->typeAlias, $this->table);
				}

				if (!$this->table->store())
				{
					$this->setError($this->table->getError());

					return false;
				}
			}
			else
			{
				$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));

				return false;
			}
		}

		// Clean the cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Batch move items to a new category
	 *
	 * @param   integer  $value     The new category ID.
	 * @param   array    $pks       An array of row IDs.
	 * @param   array    $contexts  An array of item contexts.
	 *
	 * @return  boolean  True if successful, false otherwise and internal error is set.
	 *
	 * @since	1.7
	 */
	protected function batchMove($value, $pks, $contexts)
	{
		// Initialize re-usable member properties, and re-usable local variables
		$this->initBatch();

		$categoryId = (int) $value;

		if (!$this->checkCategoryId($categoryId))
		{
			return false;
		}

		// Parent exists so we proceed
		foreach ($pks as $pk)
		{
			if (!$this->user->authorise('core.edit', $contexts[$pk]))
			{
				$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));

				return false;
			}

			// Check that the row actually exists
			if (!$this->table->load($pk))
			{
				if ($error = $this->table->getError())
				{
					// Fatal error
					$this->setError($error);

					return false;
				}
				else
				{
					// Not fatal error
					$this->setError(\JText::sprintf('JLIB_APPLICATION_ERROR_BATCH_MOVE_ROW_NOT_FOUND', $pk));
					continue;
				}
			}

			// Set the new category ID
			$this->table->catid = $categoryId;

			// Check the row.
			if (!$this->table->check())
			{
				$this->setError($this->table->getError());

				return false;
			}

			if (!empty($this->type))
			{
				$this->createTagsHelper($this->tagsObserver, $this->type, $pk, $this->typeAlias, $this->table);
			}

			// Store the row.
			if (!$this->table->store())
			{
				$this->setError($this->table->getError());

				return false;
			}
		}

		// Clean the cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Batch tag a list of item.
	 *
	 * @param   integer  $value     The value of the new tag.
	 * @param   array    $pks       An array of row IDs.
	 * @param   array    $contexts  An array of item contexts.
	 *
	 * @return  boolean  True if successful, false otherwise and internal error is set.
	 *
	 * @since   3.1
	 */
	protected function batchTag($value, $pks, $contexts)
	{
		// Initialize re-usable member properties, and re-usable local variables
		$this->initBatch();
		$tags = array($value);

		foreach ($pks as $pk)
		{
			if ($this->user->authorise('core.edit', $contexts[$pk]))
			{
				$this->table->reset();
				$this->table->load($pk);

				// Add new tags, keeping existing ones
				$result = $this->tagsObserver->setNewTags($tags, false);

				if (!$result)
				{
					$this->setError($this->table->getError());

					return false;
				}
			}
			else
			{
				$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));

				return false;
			}
		}

		// Clean the cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Method to test whether a record can be deleted.
	 *
	 * @param   object  $record  A record object.
	 *
	 * @return  boolean  True if allowed to delete the record. Defaults to the permission for the component.
	 *
	 * @since   1.6
	 */
	protected function canDelete($record)
	{
		return \JFactory::getUser()->authorise('core.delete', $this->option);
	}

	/**
	 * Method to test whether a record can have its state changed.
	 *
	 * @param   object  $record  A record object.
	 *
	 * @return  boolean  True if allowed to change the state of the record. Defaults to the permission for the component.
	 *
	 * @since   1.6
	 */
	protected function canEditState($record)
	{
		return \JFactory::getUser()->authorise('core.edit.state', $this->option);
	}

	/**
	 * Method override to check-in a record or an array of record
	 *
	 * @param   mixed  $pks  The ID of the primary key or an array of IDs
	 *
	 * @return  integer|boolean  Boolean false if there is an error, otherwise the count of records checked in.
	 *
	 * @since   1.6
	 */
	public function checkin($pks = array())
	{
		$pks = (array) $pks;
		$table = $this->getTable();
		$count = 0;

		if (empty($pks))
		{
			$pks = array((int) $this->getState($this->getName() . '.id'));
		}

		$checkedOutField = $table->getColumnAlias('checked_out');

		// Check in all items.
		foreach ($pks as $pk)
		{
			if ($table->load($pk))
			{
				if ($table->{$checkedOutField} > 0)
				{
					if (!parent::checkin($pk))
					{
						return false;
					}

					$count++;
				}
			}
			else
			{
				$this->setError($table->getError());

				return false;
			}
		}

		return $count;
	}

	/**
	 * Method override to check-out a record.
	 *
	 * @param   integer  $pk  The ID of the primary key.
	 *
	 * @return  boolean  True if successful, false if an error occurs.
	 *
	 * @since   1.6
	 */
	public function checkout($pk = null)
	{
		$pk = (!empty($pk)) ? $pk : (int) $this->getState($this->getName() . '.id');

		return parent::checkout($pk);
	}

	/**
	 * Method to delete one or more records.
	 *
	 * @param   array  &$pks  An array of record primary keys.
	 *
	 * @return  boolean  True if successful, false if an error occurs.
	 *
	 * @since   1.6
	 */
	public function delete(&$pks)
	{
		$dispatcher = \JEventDispatcher::getInstance();
		$pks = (array) $pks;
		$table = $this->getTable();

		// Include the plugins for the delete events.
		\JPluginHelper::importPlugin($this->events_map['delete']);

		// Iterate the items to delete each one.
		foreach ($pks as $i => $pk)
		{
			if ($table->load($pk))
			{
				if ($this->canDelete($table))
				{
					$context = $this->option . '.' . $this->name;

					// Trigger the before delete event.
					$result = $dispatcher->trigger($this->event_before_delete, array($context, $table));

					if (in_array(false, $result, true))
					{
						$this->setError($table->getError());

						return false;
					}

					// Multilanguage: if associated, delete the item in the _associations table
					if ($this->associationsContext && \JLanguageAssociations::isEnabled())
					{
						$db = $this->getDbo();
						$query = $db->getQuery(true)
							->select('COUNT(*) as count, ' . $db->quoteName('as1.key'))
							->from($db->quoteName('#__associations') . ' AS as1')
							->join('LEFT', $db->quoteName('#__associations') . ' AS as2 ON ' . $db->quoteName('as1.key') . ' =  ' . $db->quoteName('as2.key'))
							->where($db->quoteName('as1.context') . ' = ' . $db->quote($this->associationsContext))
							->where($db->quoteName('as1.id') . ' = ' . (int) $pk)
							->group($db->quoteName('as1.key'));

						$db->setQuery($query);
						$row = $db->loadAssoc();

						if (!empty($row['count']))
						{
							$query = $db->getQuery(true)
								->delete($db->quoteName('#__associations'))
								->where($db->quoteName('context') . ' = ' . $db->quote($this->associationsContext))
								->where($db->quoteName('key') . ' = ' . $db->quote($row['key']));

							if ($row['count'] > 2)
							{
								$query->where($db->quoteName('id') . ' = ' . (int) $pk);
							}

							$db->setQuery($query);
							$db->execute();
						}
					}

					if (!$table->delete($pk))
					{
						$this->setError($table->getError());

						return false;
					}

					// Trigger the after event.
					$dispatcher->trigger($this->event_after_delete, array($context, $table));
				}
				else
				{
					// Prune items that you can't change.
					unset($pks[$i]);
					$error = $this->getError();

					if ($error)
					{
						\JLog::add($error, \JLog::WARNING, 'jerror');

						return false;
					}
					else
					{
						\JLog::add(\JText::_('JLIB_APPLICATION_ERROR_DELETE_NOT_PERMITTED'), \JLog::WARNING, 'jerror');

						return false;
					}
				}
			}
			else
			{
				$this->setError($table->getError());

				return false;
			}
		}

		// Clear the component's cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Method to change the title & alias.
	 *
	 * @param   integer  $categoryId  The id of the category.
	 * @param   string   $alias       The alias.
	 * @param   string   $title       The title.
	 *
	 * @return	array  Contains the modified title and alias.
	 *
	 * @since	1.7
	 */
	protected function generateNewTitle($categoryId, $alias, $title)
	{
		// Alter the title & alias
		$table      = $this->getTable();
		$aliasField = $table->getColumnAlias('alias');
		$catidField = $table->getColumnAlias('catid');
		$titleField = $table->getColumnAlias('title');

		while ($table->load(array($aliasField => $alias, $catidField => $categoryId)))
		{
			if ($title === $table->$titleField)
			{
				$title = StringHelper::increment($title);
			}

			$alias = StringHelper::increment($alias, 'dash');
		}

		return array($title, $alias);
	}

	/**
	 * Method to get a single record.
	 *
	 * @param   integer  $pk  The id of the primary key.
	 *
	 * @return  \JObject|boolean  Object on success, false on failure.
	 *
	 * @since   1.6
	 */
	public function getItem($pk = null)
	{
		$pk = (!empty($pk)) ? $pk : (int) $this->getState($this->getName() . '.id');
		$table = $this->getTable();

		if ($pk > 0)
		{
			// Attempt to load the row.
			$return = $table->load($pk);

			// Check for a table object error.
			if ($return === false && $table->getError())
			{
				$this->setError($table->getError());

				return false;
			}
		}

		// Convert to the \JObject before adding other data.
		$properties = $table->getProperties(1);
		$item = ArrayHelper::toObject($properties, '\JObject');

		if (property_exists($item, 'params'))
		{
			$registry = new Registry($item->params);
			$item->params = $registry->toArray();
		}

		return $item;
	}

	/**
	 * A protected method to get a set of ordering conditions.
	 *
	 * @param   \JTable  $table  A \JTable object.
	 *
	 * @return  array  An array of conditions to add to ordering queries.
	 *
	 * @since   1.6
	 */
	protected function getReorderConditions($table)
	{
		return array();
	}

	/**
	 * Stock method to auto-populate the model state.
	 *
	 * @return  void
	 *
	 * @since   1.6
	 */
	protected function populateState()
	{
		$table = $this->getTable();
		$key = $table->getKeyName();

		// Get the pk of the record from the request.
		$pk = \JFactory::getApplication()->input->getInt($key);
		$this->setState($this->getName() . '.id', $pk);

		// Load the parameters.
		$value = \JComponentHelper::getParams($this->option);
		$this->setState('params', $value);
	}

	/**
	 * Prepare and sanitise the table data prior to saving.
	 *
	 * @param   \JTable  $table  A reference to a \JTable object.
	 *
	 * @return  void
	 *
	 * @since   1.6
	 */
	protected function prepareTable($table)
	{
		// Derived class will provide its own implementation if required.
	}

	/**
	 * Method to change the published state of one or more records.
	 *
	 * @param   array    &$pks   A list of the primary keys to change.
	 * @param   integer  $value  The value of the published state.
	 *
	 * @return  boolean  True on success.
	 *
	 * @since   1.6
	 */
	public function publish(&$pks, $value = 1)
	{
		$dispatcher = \JEventDispatcher::getInstance();
		$user = \JFactory::getUser();
		$table = $this->getTable();
		$pks = (array) $pks;

		// Include the plugins for the change of state event.
		\JPluginHelper::importPlugin($this->events_map['change_state']);

		// Access checks.
		foreach ($pks as $i => $pk)
		{
			$table->reset();

			if ($table->load($pk))
			{
				if (!$this->canEditState($table))
				{
					// Prune items that you can't change.
					unset($pks[$i]);

					\JLog::add(\JText::_('JLIB_APPLICATION_ERROR_EDITSTATE_NOT_PERMITTED'), \JLog::WARNING, 'jerror');

					return false;
				}

				// If the table is checked out by another user, drop it and report to the user trying to change its state.
				if (property_exists($table, 'checked_out') && $table->checked_out && ($table->checked_out != $user->id))
				{
					\JLog::add(\JText::_('JLIB_APPLICATION_ERROR_CHECKIN_USER_MISMATCH'), \JLog::WARNING, 'jerror');

					// Prune items that you can't change.
					unset($pks[$i]);

					return false;
				}

				/**
				 * Prune items that are already at the given state.  Note: Only models whose table correctly
				 * sets 'published' column alias (if different than published) will benefit from this
				 */
				$publishedColumnName = $table->getColumnAlias('published');

				if (property_exists($table, $publishedColumnName) && $table->get($publishedColumnName, $value) == $value)
				{
					unset($pks[$i]);

					continue;
				}
			}
		}

		// Check if there are items to change
		if (!count($pks))
		{
			return true;
		}

		// Attempt to change the state of the records.
		if (!$table->publish($pks, $value, $user->get('id')))
		{
			$this->setError($table->getError());

			return false;
		}

		$context = $this->option . '.' . $this->name;

		// Trigger the change state event.
		$result = $dispatcher->trigger($this->event_change_state, array($context, $pks, $value));

		if (in_array(false, $result, true))
		{
			$this->setError($table->getError());

			return false;
		}

		// Clear the component's cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Method to adjust the ordering of a row.
	 *
	 * Returns NULL if the user did not have edit
	 * privileges for any of the selected primary keys.
	 *
	 * @param   integer  $pks    The ID of the primary key to move.
	 * @param   integer  $delta  Increment, usually +1 or -1
	 *
	 * @return  boolean|null  False on failure or error, true on success, null if the $pk is empty (no items selected).
	 *
	 * @since   1.6
	 */
	public function reorder($pks, $delta = 0)
	{
		$table = $this->getTable();
		$pks = (array) $pks;
		$result = true;

		$allowed = true;

		foreach ($pks as $i => $pk)
		{
			$table->reset();

			if ($table->load($pk) && $this->checkout($pk))
			{
				// Access checks.
				if (!$this->canEditState($table))
				{
					// Prune items that you can't change.
					unset($pks[$i]);
					$this->checkin($pk);
					\JLog::add(\JText::_('JLIB_APPLICATION_ERROR_EDITSTATE_NOT_PERMITTED'), \JLog::WARNING, 'jerror');
					$allowed = false;
					continue;
				}

				$where = $this->getReorderConditions($table);

				if (!$table->move($delta, $where))
				{
					$this->setError($table->getError());
					unset($pks[$i]);
					$result = false;
				}

				$this->checkin($pk);
			}
			else
			{
				$this->setError($table->getError());
				unset($pks[$i]);
				$result = false;
			}
		}

		if ($allowed === false && empty($pks))
		{
			$result = null;
		}

		// Clear the component's cache
		if ($result == true)
		{
			$this->cleanCache();
		}

		return $result;
	}

	/**
	 * Method to save the form data.
	 *
	 * @param   array  $data  The form data.
	 *
	 * @return  boolean  True on success, False on error.
	 *
	 * @since   1.6
	 */
	public function save($data)
	{
		$dispatcher = \JEventDispatcher::getInstance();
		$table      = $this->getTable();
		$context    = $this->option . '.' . $this->name;
		$app        = \JFactory::getApplication();

		if (!empty($data['tags']) && $data['tags'][0] != '')
		{
			$table->newTags = $data['tags'];
		}

		$key = $table->getKeyName();
		$pk = (!empty($data[$key])) ? $data[$key] : (int) $this->getState($this->getName() . '.id');
		$isNew = true;

		// Include the plugins for the save events.
		\JPluginHelper::importPlugin($this->events_map['save']);

		// Allow an exception to be thrown.
		try
		{
			// Load the row if saving an existing record.
			if ($pk > 0)
			{
				$table->load($pk);
				$isNew = false;
			}

			// Bind the data.
			if (!$table->bind($data))
			{
				$this->setError($table->getError());

				return false;
			}

			// Prepare the row for saving
			$this->prepareTable($table);

			// Check the data.
			if (!$table->check())
			{
				$this->setError($table->getError());

				return false;
			}

			// Trigger the before save event.
			$result = $dispatcher->trigger($this->event_before_save, array($context, $table, $isNew, $data));

			if (in_array(false, $result, true))
			{
				$this->setError($table->getError());

				return false;
			}

			// Store the data.
			if (!$table->store())
			{
				$this->setError($table->getError());

				return false;
			}

			// Clean the cache.
			$this->cleanCache();

			// Trigger the after save event.
			$dispatcher->trigger($this->event_after_save, array($context, $table, $isNew, $data));
		}
		catch (\Exception $e)
		{
			$this->setError($e->getMessage());

			return false;
		}

		if (isset($table->$key))
		{
			$this->setState($this->getName() . '.id', $table->$key);
		}

		$this->setState($this->getName() . '.new', $isNew);

		if ($this->associationsContext && \JLanguageAssociations::isEnabled() && !empty($data['associations']))
		{
			$associations = $data['associations'];

			// Unset any invalid associations
			$associations = ArrayHelper::toInteger($associations);

			// Unset any invalid associations
			foreach ($associations as $tag => $id)
			{
				if (!$id)
				{
					unset($associations[$tag]);
				}
			}

			// Show a warning if the item isn't assigned to a language but we have associations.
			if ($associations && $table->language === '*')
			{
				$app->enqueueMessage(
					\JText::_(strtoupper($this->option) . '_ERROR_ALL_LANGUAGE_ASSOCIATED'),
					'warning'
				);
			}

			// Get associationskey for edited item
			$db    = $this->getDbo();
			$query = $db->getQuery(true)
				->select($db->qn('key'))
				->from($db->qn('#__associations'))
				->where($db->qn('context') . ' = ' . $db->quote($this->associationsContext))
				->where($db->qn('id') . ' = ' . (int) $table->$key);
			$db->setQuery($query);
			$old_key = $db->loadResult();

			// Deleting old associations for the associated items
			$query = $db->getQuery(true)
				->delete($db->qn('#__associations'))
				->where($db->qn('context') . ' = ' . $db->quote($this->associationsContext));

			if ($associations)
			{
				$query->where('(' . $db->qn('id') . ' IN (' . implode(',', $associations) . ') OR '
					. $db->qn('key') . ' = ' . $db->q($old_key) . ')');
			}
			else
			{
				$query->where($db->qn('key') . ' = ' . $db->q($old_key));
			}

			$db->setQuery($query);
			$db->execute();

			// Adding self to the association
			if ($table->language !== '*')
			{
				$associations[$table->language] = (int) $table->$key;
			}

			if (count($associations) > 1)
			{
				// Adding new association for these items
				$key   = md5(json_encode($associations));
				$query = $db->getQuery(true)
					->insert('#__associations');

				foreach ($associations as $id)
				{
					$query->values(((int) $id) . ',' . $db->quote($this->associationsContext) . ',' . $db->quote($key));
				}

				$db->setQuery($query);
				$db->execute();
			}
		}

		if ($app->input->get('task') == 'editAssociations')
		{
			return $this->redirectToAssociations($data);
		}

		return true;
	}

	/**
	 * Saves the manually set order of records.
	 *
	 * @param   array    $pks    An array of primary key ids.
	 * @param   integer  $order  +1 or -1
	 *
	 * @return  boolean|\JException  Boolean true on success, false on failure, or \JException if no items are selected
	 *
	 * @since   1.6
	 */
	public function saveorder($pks = array(), $order = null)
	{
		// Initialize re-usable member properties
		$this->initBatch();

		$conditions = array();

		if (empty($pks))
		{
			return \JError::raiseWarning(500, \JText::_($this->text_prefix . '_ERROR_NO_ITEMS_SELECTED'));
		}

		$orderingField = $this->table->getColumnAlias('ordering');

		// Update ordering values
		foreach ($pks as $i => $pk)
		{
			$this->table->load((int) $pk);

			// Access checks.
			if (!$this->canEditState($this->table))
			{
				// Prune items that you can't change.
				unset($pks[$i]);
				\JLog::add(\JText::_('JLIB_APPLICATION_ERROR_EDITSTATE_NOT_PERMITTED'), \JLog::WARNING, 'jerror');
			}
			elseif ($this->table->$orderingField != $order[$i])
			{
				$this->table->$orderingField = $order[$i];

				if ($this->type)
				{
					$this->createTagsHelper($this->tagsObserver, $this->type, $pk, $this->typeAlias, $this->table);
				}

				if (!$this->table->store())
				{
					$this->setError($this->table->getError());

					return false;
				}

				// Remember to reorder within position and client_id
				$condition = $this->getReorderConditions($this->table);
				$found = false;

				foreach ($conditions as $cond)
				{
					if ($cond[1] == $condition)
					{
						$found = true;
						break;
					}
				}

				if (!$found)
				{
					$key = $this->table->getKeyName();
					$conditions[] = array($this->table->$key, $condition);
				}
			}
		}

		// Execute reorder for each category.
		foreach ($conditions as $cond)
		{
			$this->table->load($cond[0]);
			$this->table->reorder($cond[1]);
		}

		// Clear the component's cache
		$this->cleanCache();

		return true;
	}

	/**
	 * Method to create a tags helper to ensure proper management of tags
	 *
	 * @param   \JTableObserverTags  $tagsObserver  The tags observer for this table
	 * @param   \JUcmType            $type          The type for the table being processed
	 * @param   integer              $pk            Primary key of the item bing processed
	 * @param   string               $typeAlias     The type alias for this table
	 * @param   \JTable              $table         The \JTable object
	 *
	 * @return  void
	 *
	 * @since   3.2
	 */
	public function createTagsHelper($tagsObserver, $type, $pk, $typeAlias, $table)
	{
		if (!empty($tagsObserver) && !empty($type))
		{
			$table->tagsHelper = new \JHelperTags;
			$table->tagsHelper->typeAlias = $typeAlias;
			$table->tagsHelper->tags = explode(',', $table->tagsHelper->getTagIds($pk, $typeAlias));
		}
	}

	/**
	 * Method to check the validity of the category ID for batch copy and move
	 *
	 * @param   integer  $categoryId  The category ID to check
	 *
	 * @return  boolean
	 *
	 * @since   3.2
	 */
	protected function checkCategoryId($categoryId)
	{
		// Check that the category exists
		if ($categoryId)
		{
			$categoryTable = \JTable::getInstance('Category');

			if (!$categoryTable->load($categoryId))
			{
				if ($error = $categoryTable->getError())
				{
					// Fatal error
					$this->setError($error);

					return false;
				}
				else
				{
					$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_MOVE_CATEGORY_NOT_FOUND'));

					return false;
				}
			}
		}

		if (empty($categoryId))
		{
			$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_MOVE_CATEGORY_NOT_FOUND'));

			return false;
		}

		// Check that the user has create permission for the component
		$extension = \JFactory::getApplication()->input->get('option', '');
		$user = \JFactory::getUser();

		if (!$user->authorise('core.create', $extension . '.category.' . $categoryId))
		{
			$this->setError(\JText::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_CREATE'));

			return false;
		}

		return true;
	}

	/**
	 * A method to preprocess generating a new title in order to allow tables with alternative names
	 * for alias and title to use the batch move and copy methods
	 *
	 * @param   integer  $categoryId  The target category id
	 * @param   \JTable  $table       The \JTable within which move or copy is taking place
	 *
	 * @return  void
	 *
	 * @since   3.2
	 */
	public function generateTitle($categoryId, $table)
	{
		// Alter the title & alias
		$titleField         = $table->getColumnAlias('title');
		$aliasField         = $table->getColumnAlias('alias');
		$data               = $this->generateNewTitle($categoryId, $table->$aliasField, $table->$titleField);
		$table->$titleField = $data['0'];
		$table->$aliasField = $data['1'];
	}

	/**
	 * Method to initialize member variables used by batch methods and other methods like saveorder()
	 *
	 * @return  void
	 *
	 * @since   3.8.2
	 */
	public function initBatch()
	{
		if ($this->batchSet === null)
		{
			$this->batchSet = true;

			// Get current user
			$this->user = \JFactory::getUser();

			// Get table
			$this->table = $this->getTable();

			// Get table class name
			$tc = explode('\\', get_class($this->table));
			$this->tableClassName = end($tc);

			// Get UCM Type data
			$this->contentType = new \JUcmType;
			$this->type = $this->contentType->getTypeByTable($this->tableClassName)
				?: $this->contentType->getTypeByAlias($this->typeAlias);

			// Get tabs observer
			$this->tagsObserver = $this->table->getObserverOfClass('Joomla\CMS\Table\Observer\Tags');
		}
	}

	/**
	 * Method to load an item in com_associations.
	 *
	 * @param   array  $data  The form data.
	 *
	 * @return  boolean  True if successful, false otherwise.
	 *
	 * @since   3.9.0
	 *
	 * @deprecated 5.0  It is handled by regular save method now.
	 */
	public function editAssociations($data)
	{
		// Save the item
		$this->save($data);
	}

	/**
	 * Method to load an item in com_associations.
	 *
	 * @param   array  $data  The form data.
	 *
	 * @return  boolean  True if successful, false otherwise.
	 *
	 * @throws \Exception
	 * @since   3.9.17
	 */
	protected function redirectToAssociations($data)
	{
		$app = Factory::getApplication();
		$id  = $data['id'];

		// Deal with categories associations
		if ($this->text_prefix === 'COM_CATEGORIES')
		{
			$extension       = $app->input->get('extension', 'com_content');
			$this->typeAlias = $extension . '.category';
			$component       = strtolower($this->text_prefix);
			$view            = 'category';
		}
		else
		{
			$aliasArray = explode('.', $this->typeAlias);
			$component  = $aliasArray[0];
			$view       = $aliasArray[1];
			$extension  = '';
		}

		// Menu item redirect needs admin client
		$client = $component === 'com_menus' ? '&client_id=0' : '';

		if ($id == 0)
		{
			$app->enqueueMessage(\JText::_('JGLOBAL_ASSOCIATIONS_NEW_ITEM_WARNING'), 'error');
			$app->redirect(
				\JRoute::_('index.php?option=' . $component . '&view=' . $view . $client . '&layout=edit&id=' . $id . $extension, false)
			);

			return false;
		}

		if ($data['language'] === '*')
		{
			$app->enqueueMessage(\JText::_('JGLOBAL_ASSOC_NOT_POSSIBLE'), 'notice');
			$app->redirect(
				\JRoute::_('index.php?option=' . $component . '&view=' . $view . $client . '&layout=edit&id=' . $id . $extension, false)
			);

			return false;
		}

		$languages = LanguageHelper::getContentLanguages(array(0, 1));
		$target    = '';

		/* If the site contains only 2 languages and an association exists for the item
		   load directly the associated target item in the side by side view
		   otherwise select already the target language
		*/
		if (count($languages) === 2)
		{
			foreach ($languages as $language)
			{
				$lang_code[] = $language->lang_code;
			}

			$refLang    = array($data['language']);
			$targetLang = array_diff($lang_code, $refLang);
			$targetLang = implode(',', $targetLang);
			$targetId   = $data['associations'][$targetLang];

			if ($targetId)
			{
				$target = '&target=' . $targetLang . '%3A' . $targetId . '%3Aedit';
			}
			else
			{
				$target = '&target=' . $targetLang . '%3A0%3Aadd';
			}
		}

		$app->redirect(
			\JRoute::_(
				'index.php?option=com_associations&view=association&layout=edit&itemtype=' . $this->typeAlias
				. '&task=association.edit&id=' . $id . $target, false
			)
		);

		return true;
	}
}
