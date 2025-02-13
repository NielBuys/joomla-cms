<?php
/**
 * @package     Joomla.Platform
 * @subpackage  Database
 *
 * @copyright   (C) 2006 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('JPATH_PLATFORM') or die;

/**
 * Query Building Class.
 *
 * @since  1.7.0
 *
 * @method      string  q()   q($text, $escape = true)  Alias for quote method
 * @method      string  qn()  qn($name, $as = null)     Alias for quoteName method
 * @method      string  e()   e($text, $extra = false)  Alias for escape method
 * @property-read   JDatabaseQueryElement  $type
 * @property-read   JDatabaseQueryElement  $select
 * @property-read   JDatabaseQueryElement  $group
 * @property-read   JDatabaseQueryElement  $having
 */
abstract class JDatabaseQuery
{
	/**
	 * @var    JDatabaseDriver  The database driver.
	 * @since  1.7.0
	 */
	protected $db = null;

	/**
	 * @var    string  The SQL query (if a direct query string was provided).
	 * @since  3.0.0
	 */
	protected $sql = null;

	/**
	 * @var    string  The query type.
	 * @since  1.7.0
	 */
	protected $type = '';

	/**
	 * @var    JDatabaseQueryElement  The query element for a generic query (type = null).
	 * @since  1.7.0
	 */
	protected $element = null;

	/**
	 * @var    JDatabaseQueryElement  The select element.
	 * @since  1.7.0
	 */
	protected $select = null;

	/**
	 * @var    JDatabaseQueryElement  The delete element.
	 * @since  1.7.0
	 */
	protected $delete = null;

	/**
	 * @var    JDatabaseQueryElement  The update element.
	 * @since  1.7.0
	 */
	protected $update = null;

	/**
	 * @var    JDatabaseQueryElement  The insert element.
	 * @since  1.7.0
	 */
	protected $insert = null;

	/**
	 * @var    JDatabaseQueryElement  The from element.
	 * @since  1.7.0
	 */
	protected $from = null;

	/**
	 * @var    JDatabaseQueryElement  The join element.
	 * @since  1.7.0
	 */
	protected $join = null;

	/**
	 * @var    JDatabaseQueryElement  The set element.
	 * @since  1.7.0
	 */
	protected $set = null;

	/**
	 * @var    JDatabaseQueryElement  The where element.
	 * @since  1.7.0
	 */
	protected $where = null;

	/**
	 * @var    JDatabaseQueryElement  The group by element.
	 * @since  1.7.0
	 */
	protected $group = null;

	/**
	 * @var    JDatabaseQueryElement  The having element.
	 * @since  1.7.0
	 */
	protected $having = null;

	/**
	 * @var    JDatabaseQueryElement  The column list for an INSERT statement.
	 * @since  1.7.0
	 */
	protected $columns = null;

	/**
	 * @var    JDatabaseQueryElement  The values list for an INSERT statement.
	 * @since  1.7.0
	 */
	protected $values = null;

	/**
	 * @var    JDatabaseQueryElement  The order element.
	 * @since  1.7.0
	 */
	protected $order = null;

	/**
	 * @var   object  The auto increment insert field element.
	 * @since 1.7.0
	 */
	protected $autoIncrementField = null;

	/**
	 * @var    JDatabaseQueryElement  The call element.
	 * @since  3.0.0
	 */
	protected $call = null;

	/**
	 * @var    JDatabaseQueryElement  The exec element.
	 * @since  3.0.0
	 */
	protected $exec = null;

	/**
	 * @var    JDatabaseQueryElement  The union element.
	 * @since  3.0.0
	 * @deprecated  4.0  Will be transformed and moved to $merge variable.
	 */
	protected $union = null;

	/**
	 * @var    JDatabaseQueryElement  The unionAll element.
	 * @since  3.2.0
	 * @deprecated  4.0  Will be transformed and moved to $merge variable.
	 */
	protected $unionAll = null;

	/**
	 * @var    array  Details of window function.
	 * @since  3.7.0
	 */
	protected $selectRowNumber = null;

	/**
	 * Magic method to provide method alias support for quote() and quoteName().
	 *
	 * @param   string  $method  The called method.
	 * @param   array   $args    The array of arguments passed to the method.
	 *
	 * @return  string  The aliased method's return value or null.
	 *
	 * @since   1.7.0
	 */
	public function __call($method, $args)
	{
		if (empty($args))
		{
			return;
		}

		switch ($method)
		{
			case 'q':
				return $this->quote($args[0], isset($args[1]) ? $args[1] : true);
				break;

			case 'qn':
				return $this->quoteName($args[0], isset($args[1]) ? $args[1] : null);
				break;

			case 'e':
				return $this->escape($args[0], isset($args[1]) ? $args[1] : false);
				break;
		}
	}

	/**
	 * Class constructor.
	 *
	 * @param   JDatabaseDriver  $db  The database driver.
	 *
	 * @since   1.7.0
	 */
	public function __construct(?JDatabaseDriver $db = null)
	{
		$this->db = $db;
	}

	/**
	 * Magic function to convert the query to a string.
	 *
	 * @return  string	The completed query.
	 *
	 * @since   1.7.0
	 */
	public function __toString()
	{
		$query = '';

		if ($this->sql)
		{
			return $this->sql;
		}

		switch ($this->type)
		{
			case 'element':
				$query .= (string) $this->element;
				break;

			case 'select':
				$query .= (string) $this->select;
				$query .= (string) $this->from;

				if ($this->join)
				{
					// Special case for joins
					foreach ($this->join as $join)
					{
						$query .= (string) $join;
					}
				}

				if ($this->where)
				{
					$query .= (string) $this->where;
				}

				if ($this->selectRowNumber === null)
				{
					if ($this->group)
					{
						$query .= (string) $this->group;
					}

					if ($this->having)
					{
						$query .= (string) $this->having;
					}

					if ($this->union)
					{
						$query .= (string) $this->union;
					}

					if ($this->unionAll)
					{
						$query .= (string) $this->unionAll;
					}
				}

				if ($this->order)
				{
					$query .= (string) $this->order;
				}

				break;

			case 'delete':
				$query .= (string) $this->delete;
				$query .= (string) $this->from;

				if ($this->join)
				{
					// Special case for joins
					foreach ($this->join as $join)
					{
						$query .= (string) $join;
					}
				}

				if ($this->where)
				{
					$query .= (string) $this->where;
				}

				if ($this->order)
				{
					$query .= (string) $this->order;
				}

				break;

			case 'update':
				$query .= (string) $this->update;

				if ($this->join)
				{
					// Special case for joins
					foreach ($this->join as $join)
					{
						$query .= (string) $join;
					}
				}

				$query .= (string) $this->set;

				if ($this->where)
				{
					$query .= (string) $this->where;
				}

				if ($this->order)
				{
					$query .= (string) $this->order;
				}

				break;

			case 'insert':
				$query .= (string) $this->insert;

				// Set method
				if ($this->set)
				{
					$query .= (string) $this->set;
				}
				// Columns-Values method
				elseif ($this->values)
				{
					if ($this->columns)
					{
						$query .= (string) $this->columns;
					}

					$elements = $this->values->getElements();

					if (!($elements[0] instanceof $this))
					{
						$query .= ' VALUES ';
					}

					$query .= (string) $this->values;
				}

				break;

			case 'call':
				$query .= (string) $this->call;
				break;

			case 'exec':
				$query .= (string) $this->exec;
				break;
		}

		if ($this instanceof JDatabaseQueryLimitable)
		{
			$query = $this->processLimit($query, $this->limit, $this->offset);
		}

		return $query;
	}

	/**
	 * Magic function to get protected variable value
	 *
	 * @param   string  $name  The name of the variable.
	 *
	 * @return  mixed
	 *
	 * @since   1.7.0
	 */
	public function __get($name)
	{
		return isset($this->$name) ? $this->$name : null;
	}

	/**
	 * Add a single column, or array of columns to the CALL clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 * The call method can, however, be called multiple times in the same query.
	 *
	 * Usage:
	 * $query->call('a.*')->call('b.id');
	 * $query->call(array('a.*', 'b.id'));
	 *
	 * @param   mixed  $columns  A string or an array of field names.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.0.0
	 */
	public function call($columns)
	{
		$this->type = 'call';

		if (is_null($this->call))
		{
			$this->call = new JDatabaseQueryElement('CALL', $columns);
		}
		else
		{
			$this->call->append($columns);
		}

		return $this;
	}

	/**
	 * Casts a value to a char.
	 *
	 * Ensure that the value is properly quoted before passing to the method.
	 *
	 * Usage:
	 * $query->select($query->castAsChar('a'));
	 *
	 * @param   string  $value  The value to cast as a char.
	 *
	 * @return  string  Returns the cast value.
	 *
	 * @since   1.7.0
	 */
	public function castAsChar($value)
	{
		return $value;
	}

	/**
	 * Gets the number of characters in a string.
	 *
	 * Note, use 'length' to find the number of bytes in a string.
	 *
	 * Usage:
	 * $query->select($query->charLength('a'));
	 *
	 * @param   string  $field      A value.
	 * @param   string  $operator   Comparison operator between charLength integer value and $condition
	 * @param   string  $condition  Integer value to compare charLength with.
	 *
	 * @return  string  The required char length call.
	 *
	 * @since   1.7.0
	 */
	public function charLength($field, $operator = null, $condition = null)
	{
		return 'CHAR_LENGTH(' . $field . ')' . (isset($operator) && isset($condition) ? ' ' . $operator . ' ' . $condition : '');
	}

	/**
	 * Clear data from the query or a specific clause of the query.
	 *
	 * @param   string  $clause  Optionally, the name of the clause to clear, or nothing to clear the whole query.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function clear($clause = null)
	{
		$this->sql = null;

		switch ($clause)
		{
			case 'select':
				$this->select = null;
				$this->type = null;
				$this->selectRowNumber = null;
				break;

			case 'delete':
				$this->delete = null;
				$this->type = null;
				break;

			case 'update':
				$this->update = null;
				$this->type = null;
				break;

			case 'insert':
				$this->insert = null;
				$this->type = null;
				$this->autoIncrementField = null;
				break;

			case 'from':
				$this->from = null;
				break;

			case 'join':
				$this->join = null;
				break;

			case 'set':
				$this->set = null;
				break;

			case 'where':
				$this->where = null;
				break;

			case 'group':
				$this->group = null;
				break;

			case 'having':
				$this->having = null;
				break;

			case 'order':
				$this->order = null;
				break;

			case 'columns':
				$this->columns = null;
				break;

			case 'values':
				$this->values = null;
				break;

			case 'exec':
				$this->exec = null;
				$this->type = null;
				break;

			case 'call':
				$this->call = null;
				$this->type = null;
				break;

			case 'limit':
				$this->offset = 0;
				$this->limit = 0;
				break;

			case 'offset':
				$this->offset = 0;
				break;

			case 'union':
				$this->union = null;
				break;

			case 'unionAll':
				$this->unionAll = null;
				break;

			default:
				$this->type = null;
				$this->select = null;
				$this->selectRowNumber = null;
				$this->delete = null;
				$this->update = null;
				$this->insert = null;
				$this->from = null;
				$this->join = null;
				$this->set = null;
				$this->where = null;
				$this->group = null;
				$this->having = null;
				$this->order = null;
				$this->columns = null;
				$this->values = null;
				$this->autoIncrementField = null;
				$this->exec = null;
				$this->call = null;
				$this->union = null;
				$this->unionAll = null;
				$this->offset = 0;
				$this->limit = 0;
				break;
		}

		return $this;
	}

	/**
	 * Adds a column, or array of column names that would be used for an INSERT INTO statement.
	 *
	 * @param   mixed  $columns  A column name, or array of column names.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function columns($columns)
	{
		if (is_null($this->columns))
		{
			$this->columns = new JDatabaseQueryElement('()', $columns);
		}
		else
		{
			$this->columns->append($columns);
		}

		return $this;
	}

	/**
	 * Concatenates an array of column names or values.
	 *
	 * Usage:
	 * $query->select($query->concatenate(array('a', 'b')));
	 *
	 * @param   array   $values     An array of values to concatenate.
	 * @param   string  $separator  As separator to place between each value.
	 *
	 * @return  string  The concatenated values.
	 *
	 * @since   1.7.0
	 */
	public function concatenate($values, $separator = null)
	{
		if ($separator)
		{
			return 'CONCATENATE(' . implode(' || ' . $this->quote($separator) . ' || ', $values) . ')';
		}
		else
		{
			return 'CONCATENATE(' . implode(' || ', $values) . ')';
		}
	}

	/**
	 * Gets the current date and time.
	 *
	 * Usage:
	 * $query->where('published_up < '.$query->currentTimestamp());
	 *
	 * @return  string
	 *
	 * @since   1.7.0
	 */
	public function currentTimestamp()
	{
		return 'CURRENT_TIMESTAMP()';
	}

	/**
	 * Returns a PHP date() function compliant date format for the database driver.
	 *
	 * This method is provided for use where the query object is passed to a function for modification.
	 * If you have direct access to the database object, it is recommended you use the getDateFormat method directly.
	 *
	 * @return  string  The format string.
	 *
	 * @since   1.7.0
	 */
	public function dateFormat()
	{
		if (!($this->db instanceof JDatabaseDriver))
		{
			throw new RuntimeException('JLIB_DATABASE_ERROR_INVALID_DB_OBJECT');
		}

		return $this->db->getDateFormat();
	}

	/**
	 * Creates a formatted dump of the query for debugging purposes.
	 *
	 * Usage:
	 * echo $query->dump();
	 *
	 * @return  string
	 *
	 * @since   1.7.3
	 */
	public function dump()
	{
		return '<pre class="jdatabasequery">' . str_replace('#__', $this->db->getPrefix(), $this) . '</pre>';
	}

	/**
	 * Add a table name to the DELETE clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 *
	 * Usage:
	 * $query->delete('#__a')->where('id = 1');
	 *
	 * @param   string  $table  The name of the table to delete from.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function delete($table = null)
	{
		$this->type = 'delete';
		$this->delete = new JDatabaseQueryElement('DELETE', null);

		if (!empty($table))
		{
			$this->from($table);
		}

		return $this;
	}

	/**
	 * Method to escape a string for usage in an SQL statement.
	 *
	 * This method is provided for use where the query object is passed to a function for modification.
	 * If you have direct access to the database object, it is recommended you use the escape method directly.
	 *
	 * Note that 'e' is an alias for this method as it is in JDatabaseDriver.
	 *
	 * @param   string   $text   The string to be escaped.
	 * @param   boolean  $extra  Optional parameter to provide extra escaping.
	 *
	 * @return  string  The escaped string.
	 *
	 * @since   1.7.0
	 * @throws  RuntimeException if the internal db property is not a valid object.
	 */
	public function escape($text, $extra = false)
	{
		if (!($this->db instanceof JDatabaseDriver))
		{
			throw new RuntimeException('JLIB_DATABASE_ERROR_INVALID_DB_OBJECT');
		}

		return $this->db->escape($text, $extra);
	}

	/**
	 * Add a single column, or array of columns to the EXEC clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 * The exec method can, however, be called multiple times in the same query.
	 *
	 * Usage:
	 * $query->exec('a.*')->exec('b.id');
	 * $query->exec(array('a.*', 'b.id'));
	 *
	 * @param   mixed  $columns  A string or an array of field names.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.0.0
	 */
	public function exec($columns)
	{
		$this->type = 'exec';

		if (is_null($this->exec))
		{
			$this->exec = new JDatabaseQueryElement('EXEC', $columns);
		}
		else
		{
			$this->exec->append($columns);
		}

		return $this;
	}

	/**
	 * Add a table to the FROM clause of the query.
	 *
	 * Note that while an array of tables can be provided, it is recommended you use explicit joins.
	 *
	 * Usage:
	 * $query->select('*')->from('#__a');
	 *
	 * @param   mixed   $tables         A string or array of table names.
	 *                                  This can be a JDatabaseQuery object (or a child of it) when used
	 *                                  as a subquery in FROM clause along with a value for $subQueryAlias.
	 * @param   string  $subQueryAlias  Alias used when $tables is a JDatabaseQuery.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @throws  RuntimeException
	 *
	 * @since   1.7.0
	 */
	public function from($tables, $subQueryAlias = null)
	{
		if (is_null($this->from))
		{
			if ($tables instanceof $this)
			{
				if (is_null($subQueryAlias))
				{
					throw new RuntimeException('JLIB_DATABASE_ERROR_NULL_SUBQUERY_ALIAS');
				}

				$tables = '( ' . (string) $tables . ' ) AS ' . $this->quoteName($subQueryAlias);
			}

			$this->from = new JDatabaseQueryElement('FROM', $tables);
		}
		else
		{
			$this->from->append($tables);
		}

		return $this;
	}

	/**
	 * Used to get a string to extract year from date column.
	 *
	 * Usage:
	 * $query->select($query->year($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing year to be extracted.
	 *
	 * @return  string  Returns string to extract year from a date.
	 *
	 * @since   3.0.0
	 */
	public function year($date)
	{
		return 'YEAR(' . $date . ')';
	}

	/**
	 * Used to get a string to extract month from date column.
	 *
	 * Usage:
	 * $query->select($query->month($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing month to be extracted.
	 *
	 * @return  string  Returns string to extract month from a date.
	 *
	 * @since   3.0.0
	 */
	public function month($date)
	{
		return 'MONTH(' . $date . ')';
	}

	/**
	 * Used to get a string to extract day from date column.
	 *
	 * Usage:
	 * $query->select($query->day($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing day to be extracted.
	 *
	 * @return  string  Returns string to extract day from a date.
	 *
	 * @since   3.0.0
	 */
	public function day($date)
	{
		return 'DAY(' . $date . ')';
	}

	/**
	 * Used to get a string to extract hour from date column.
	 *
	 * Usage:
	 * $query->select($query->hour($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing hour to be extracted.
	 *
	 * @return  string  Returns string to extract hour from a date.
	 *
	 * @since   3.0.0
	 */
	public function hour($date)
	{
		return 'HOUR(' . $date . ')';
	}

	/**
	 * Used to get a string to extract minute from date column.
	 *
	 * Usage:
	 * $query->select($query->minute($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing minute to be extracted.
	 *
	 * @return  string  Returns string to extract minute from a date.
	 *
	 * @since   3.0.0
	 */
	public function minute($date)
	{
		return 'MINUTE(' . $date . ')';
	}

	/**
	 * Used to get a string to extract seconds from date column.
	 *
	 * Usage:
	 * $query->select($query->second($query->quoteName('dateColumn')));
	 *
	 * @param   string  $date  Date column containing second to be extracted.
	 *
	 * @return  string  Returns string to extract second from a date.
	 *
	 * @since   3.0.0
	 */
	public function second($date)
	{
		return 'SECOND(' . $date . ')';
	}

	/**
	 * Add a grouping column to the GROUP clause of the query.
	 *
	 * Usage:
	 * $query->group('id');
	 *
	 * @param   mixed  $columns  A string or array of ordering columns.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function group($columns)
	{
		if (is_null($this->group))
		{
			$this->group = new JDatabaseQueryElement('GROUP BY', $columns);
		}
		else
		{
			$this->group->append($columns);
		}

		return $this;
	}

	/**
	 * A conditions to the HAVING clause of the query.
	 *
	 * Usage:
	 * $query->group('id')->having('COUNT(id) > 5');
	 *
	 * @param   mixed   $conditions  A string or array of columns.
	 * @param   string  $glue        The glue by which to join the conditions. Defaults to AND.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function having($conditions, $glue = 'AND')
	{
		if (is_null($this->having))
		{
			$glue = strtoupper($glue);
			$this->having = new JDatabaseQueryElement('HAVING', $conditions, " $glue ");
		}
		else
		{
			$this->having->append($conditions);
		}

		return $this;
	}

	/**
	 * Add an INNER JOIN clause to the query.
	 *
	 * Usage:
	 * $query->innerJoin('b ON b.id = a.id')->innerJoin('c ON c.id = b.id');
	 *
	 * @param   string  $condition  The join condition.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function innerJoin($condition)
	{
		$this->join('INNER', $condition);

		return $this;
	}

	/**
	 * Add a table name to the INSERT clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 *
	 * Usage:
	 * $query->insert('#__a')->set('id = 1');
	 * $query->insert('#__a')->columns('id, title')->values('1,2')->values('3,4');
	 * $query->insert('#__a')->columns('id, title')->values(array('1,2', '3,4'));
	 *
	 * @param   mixed    $table           The name of the table to insert data into.
	 * @param   boolean  $incrementField  The name of the field to auto increment.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function insert($table, $incrementField=false)
	{
		$this->type = 'insert';
		$this->insert = new JDatabaseQueryElement('INSERT INTO', $table);
		$this->autoIncrementField = $incrementField;

		return $this;
	}

	/**
	 * Add a JOIN clause to the query.
	 *
	 * Usage:
	 * $query->join('INNER', 'b ON b.id = a.id);
	 *
	 * @param   string  $type        The type of join. This string is prepended to the JOIN keyword.
	 * @param   string  $conditions  A string or array of conditions.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function join($type, $conditions)
	{
		if (is_null($this->join))
		{
			$this->join = array();
		}

		$this->join[] = new JDatabaseQueryElement(strtoupper($type) . ' JOIN', $conditions);

		return $this;
	}

	/**
	 * Add a LEFT JOIN clause to the query.
	 *
	 * Usage:
	 * $query->leftJoin('b ON b.id = a.id')->leftJoin('c ON c.id = b.id');
	 *
	 * @param   string  $condition  The join condition.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function leftJoin($condition)
	{
		$this->join('LEFT', $condition);

		return $this;
	}

	/**
	 * Get the length of a string in bytes.
	 *
	 * Note, use 'charLength' to find the number of characters in a string.
	 *
	 * Usage:
	 * query->where($query->length('a').' > 3');
	 *
	 * @param   string  $value  The string to measure.
	 *
	 * @return  int
	 *
	 * @since   1.7.0
	 */
	public function length($value)
	{
		return 'LENGTH(' . $value . ')';
	}

	/**
	 * Get the null or zero representation of a timestamp for the database driver.
	 *
	 * This method is provided for use where the query object is passed to a function for modification.
	 * If you have direct access to the database object, it is recommended you use the nullDate method directly.
	 *
	 * Usage:
	 * $query->where('modified_date <> '.$query->nullDate());
	 *
	 * @param   boolean  $quoted  Optionally wraps the null date in database quotes (true by default).
	 *
	 * @return  string  Null or zero representation of a timestamp.
	 *
	 * @since   1.7.0
	 */
	public function nullDate($quoted = true)
	{
		if (!($this->db instanceof JDatabaseDriver))
		{
			throw new RuntimeException('JLIB_DATABASE_ERROR_INVALID_DB_OBJECT');
		}

		$result = $this->db->getNullDate($quoted);

		if ($quoted)
		{
			return $this->db->quote($result);
		}

		return $result;
	}

	/**
	 * Add an ordering column to the ORDER clause of the query.
	 *
	 * Usage:
	 * $query->order('foo')->order('bar');
	 * $query->order(array('foo','bar'));
	 *
	 * @param   mixed  $columns  A string or array of ordering columns.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function order($columns)
	{
		if (is_null($this->order))
		{
			$this->order = new JDatabaseQueryElement('ORDER BY', $columns);
		}
		else
		{
			$this->order->append($columns);
		}

		return $this;
	}

	/**
	 * Add an OUTER JOIN clause to the query.
	 *
	 * Usage:
	 * $query->outerJoin('b ON b.id = a.id')->outerJoin('c ON c.id = b.id');
	 *
	 * @param   string  $condition  The join condition.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function outerJoin($condition)
	{
		$this->join('OUTER', $condition);

		return $this;
	}

	/**
	 * Method to quote and optionally escape a string to database requirements for insertion into the database.
	 *
	 * This method is provided for use where the query object is passed to a function for modification.
	 * If you have direct access to the database object, it is recommended you use the quote method directly.
	 *
	 * Note that 'q' is an alias for this method as it is in JDatabaseDriver.
	 *
	 * Usage:
	 * $query->quote('fulltext');
	 * $query->q('fulltext');
	 * $query->q(array('option', 'fulltext'));
	 *
	 * @param   mixed    $text    A string or an array of strings to quote.
	 * @param   boolean  $escape  True to escape the string, false to leave it unchanged.
	 *
	 * @return  string  The quoted input string.
	 *
	 * @since   1.7.0
	 * @throws  RuntimeException if the internal db property is not a valid object.
	 */
	public function quote($text, $escape = true)
	{
		if (!($this->db instanceof JDatabaseDriver))
		{
			throw new RuntimeException('JLIB_DATABASE_ERROR_INVALID_DB_OBJECT');
		}

		return $this->db->quote($text, $escape);
	}

	/**
	 * Wrap an SQL statement identifier name such as column, table or database names in quotes to prevent injection
	 * risks and reserved word conflicts.
	 *
	 * This method is provided for use where the query object is passed to a function for modification.
	 * If you have direct access to the database object, it is recommended you use the quoteName method directly.
	 *
	 * Note that 'qn' is an alias for this method as it is in JDatabaseDriver.
	 *
	 * Usage:
	 * $query->quoteName('#__a');
	 * $query->qn('#__a');
	 *
	 * @param   mixed  $name  The identifier name to wrap in quotes, or an array of identifier names to wrap in quotes.
	 *                        Each type supports dot-notation name.
	 * @param   mixed  $as    The AS query part associated to $name. It can be string or array, in latter case it has to be
	 *                        same length of $name; if is null there will not be any AS part for string or array element.
	 *
	 * @return  mixed  The quote wrapped name, same type of $name.
	 *
	 * @since   1.7.0
	 * @throws  RuntimeException if the internal db property is not a valid object.
	 */
	public function quoteName($name, $as = null)
	{
		if (!($this->db instanceof JDatabaseDriver))
		{
			throw new RuntimeException('JLIB_DATABASE_ERROR_INVALID_DB_OBJECT');
		}

		return $this->db->quoteName($name, $as);
	}

	/**
	 * Add a RIGHT JOIN clause to the query.
	 *
	 * Usage:
	 * $query->rightJoin('b ON b.id = a.id')->rightJoin('c ON c.id = b.id');
	 *
	 * @param   string  $condition  The join condition.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function rightJoin($condition)
	{
		$this->join('RIGHT', $condition);

		return $this;
	}

	/**
	 * Add a single column, or array of columns to the SELECT clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 * The select method can, however, be called multiple times in the same query.
	 *
	 * Usage:
	 * $query->select('a.*')->select('b.id');
	 * $query->select(array('a.*', 'b.id'));
	 *
	 * @param   mixed  $columns  A string or an array of field names.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function select($columns)
	{
		$this->type = 'select';

		if (is_null($this->select))
		{
			$this->select = new JDatabaseQueryElement('SELECT', $columns);
		}
		else
		{
			$this->select->append($columns);
		}

		return $this;
	}

	/**
	 * Add a single condition string, or an array of strings to the SET clause of the query.
	 *
	 * Usage:
	 * $query->set('a = 1')->set('b = 2');
	 * $query->set(array('a = 1', 'b = 2');
	 *
	 * @param   mixed   $conditions  A string or array of string conditions.
	 * @param   string  $glue        The glue by which to join the condition strings. Defaults to ,.
	 *                               Note that the glue is set on first use and cannot be changed.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function set($conditions, $glue = ',')
	{
		if (is_null($this->set))
		{
			$glue = strtoupper($glue);
			$this->set = new JDatabaseQueryElement('SET', $conditions, "\n\t$glue ");
		}
		else
		{
			$this->set->append($conditions);
		}

		return $this;
	}

	/**
	 * Allows a direct query to be provided to the database
	 * driver's setQuery() method, but still allow queries
	 * to have bounded variables.
	 *
	 * Usage:
	 * $query->setQuery('select * from #__users');
	 *
	 * @param   mixed  $sql  An SQL Query
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.0.0
	 */
	public function setQuery($sql)
	{
		$this->sql = $sql;

		return $this;
	}

	/**
	 * Add a table name to the UPDATE clause of the query.
	 *
	 * Note that you must not mix insert, update, delete and select method calls when building a query.
	 *
	 * Usage:
	 * $query->update('#__foo')->set(...);
	 *
	 * @param   string  $table  A table to update.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function update($table)
	{
		$this->type = 'update';
		$this->update = new JDatabaseQueryElement('UPDATE', $table);

		return $this;
	}

	/**
	 * Adds a tuple, or array of tuples that would be used as values for an INSERT INTO statement.
	 *
	 * Usage:
	 * $query->values('1,2,3')->values('4,5,6');
	 * $query->values(array('1,2,3', '4,5,6'));
	 *
	 * @param   string  $values  A single tuple, or array of tuples.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function values($values)
	{
		if (is_null($this->values))
		{
			$this->values = new JDatabaseQueryElement('()', $values, '),(');
		}
		else
		{
			$this->values->append($values);
		}

		return $this;
	}

	/**
	 * Add a single condition, or an array of conditions to the WHERE clause of the query.
	 *
	 * Usage:
	 * $query->where('a = 1')->where('b = 2');
	 * $query->where(array('a = 1', 'b = 2'));
	 *
	 * @param   mixed   $conditions  A string or array of where conditions.
	 * @param   string  $glue        The glue by which to join the conditions. Defaults to AND.
	 *                               Note that the glue is set on first use and cannot be changed.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   1.7.0
	 */
	public function where($conditions, $glue = 'AND')
	{
		if (is_null($this->where))
		{
			$glue = strtoupper($glue);
			$this->where = new JDatabaseQueryElement('WHERE', $conditions, " $glue ");
		}
		else
		{
			$this->where->append($conditions);
		}

		return $this;
	}

	/**
	 * Extend the WHERE clause with a single condition or an array of conditions, with a potentially
	 * different logical operator from the one in the current WHERE clause.
	 *
	 * Usage:
	 * $query->where(array('a = 1', 'b = 2'))->extendWhere('XOR', array('c = 3', 'd = 4'));
	 * will produce: WHERE ((a = 1 AND b = 2) XOR (c = 3 AND d = 4)
	 *
	 * @param   string  $outerGlue   The glue by which to join the conditions to the current WHERE conditions.
	 * @param   mixed   $conditions  A string or array of WHERE conditions.
	 * @param   string  $innerGlue   The glue by which to join the conditions. Defaults to AND.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.6
	 */
	public function extendWhere($outerGlue, $conditions, $innerGlue = 'AND')
	{
		// Replace the current WHERE with a new one which has the old one as an unnamed child.
		$this->where = new JDatabaseQueryElement('WHERE', $this->where->setName('()'), " $outerGlue ");

		// Append the new conditions as a new unnamed child.
		$this->where->append(new JDatabaseQueryElement('()', $conditions, " $innerGlue "));

		return $this;
	}

	/**
	 * Extend the WHERE clause with an OR and a single condition or an array of conditions.
	 *
	 * Usage:
	 * $query->where(array('a = 1', 'b = 2'))->orWhere(array('c = 3', 'd = 4'));
	 * will produce: WHERE ((a = 1 AND b = 2) OR (c = 3 AND d = 4)
	 *
	 * @param   mixed   $conditions  A string or array of WHERE conditions.
	 * @param   string  $glue        The glue by which to join the conditions. Defaults to AND.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.6
	 */
	public function orWhere($conditions, $glue = 'AND')
	{
		return $this->extendWhere('OR', $conditions, $glue);
	}

	/**
	 * Extend the WHERE clause with an AND and a single condition or an array of conditions.
	 *
	 * Usage:
	 * $query->where(array('a = 1', 'b = 2'))->andWhere(array('c = 3', 'd = 4'));
	 * will produce: WHERE ((a = 1 AND b = 2) AND (c = 3 OR d = 4)
	 *
	 * @param   mixed   $conditions  A string or array of WHERE conditions.
	 * @param   string  $glue        The glue by which to join the conditions. Defaults to OR.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.6
	 */
	public function andWhere($conditions, $glue = 'OR')
	{
		return $this->extendWhere('AND', $conditions, $glue);
	}

	/**
	 * Method to provide deep copy support to nested objects and
	 * arrays when cloning.
	 *
	 * @return  void
	 *
	 * @since   1.7.3
	 */
	public function __clone()
	{
		foreach ($this as $k => $v)
		{
			if ($k === 'db')
			{
				continue;
			}

			if (is_object($v) || is_array($v))
			{
				$this->{$k} = unserialize(serialize($v));
			}
		}
	}

	/**
	 * Add a query to UNION with the current query.
	 * Multiple unions each require separate statements and create an array of unions.
	 *
	 * Usage (the $query base query MUST be a select query):
	 * $query->union('SELECT name FROM  #__foo')
	 * $query->union('SELECT name FROM  #__foo', true)
	 * $query->union($query2)->union($query3)
	 *
	 * The $query attribute as an array is deprecated and will not be supported in 4.0.
	 *
	 * $query->union(array('SELECT name FROM  #__foo','SELECT name FROM  #__bar'))
	 * $query->union(array($query2, $query3))
	 *
	 * @param   mixed    $query     The JDatabaseQuery object or string to union.
	 * @param   boolean  $distinct  True to only return distinct rows from the union.
	 * @param   string   $glue      The glue by which to join the conditions.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @link http://dev.mysql.com/doc/refman/5.0/en/union.html
	 *
	 * @since   3.0.0
	 */
	public function union($query, $distinct = false, $glue = '')
	{
		// Set up the DISTINCT flag, the name with parentheses, and the glue.
		if ($distinct)
		{
			$name = 'UNION DISTINCT ()';
			$glue = ')' . PHP_EOL . 'UNION DISTINCT (';
		}
		else
		{
			$glue = ')' . PHP_EOL . 'UNION (';
			$name = 'UNION ()';
		}

		if (is_array($query))
		{
			JLog::add('Query attribute as an array is deprecated.', JLog::WARNING, 'deprecated');
		}

		// Get the JDatabaseQueryElement if it does not exist
		if (is_null($this->union))
		{
			$this->union = new JDatabaseQueryElement($name, $query, "$glue");
		}
		// Otherwise append the second UNION.
		else
		{
			$this->union->append($query);
		}

		return $this;
	}

	/**
	 * Add a query to UNION DISTINCT with the current query. Simply a proxy to union with the DISTINCT keyword.
	 *
	 * Usage:
	 * $query->unionDistinct('SELECT name FROM  #__foo')
	 *
	 * @param   mixed   $query  The JDatabaseQuery object or string to union.
	 * @param   string  $glue   The glue by which to join the conditions.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @see     union
	 *
	 * @since   3.0.0
	 * @deprecated  4.0  Use union() instead.
	 */
	public function unionDistinct($query, $glue = '')
	{
		$distinct = true;

		// Apply the distinct flag to the union.
		return $this->union($query, $distinct, $glue);
	}

	/**
	 * Find and replace sprintf-like tokens in a format string.
	 * Each token takes one of the following forms:
	 *     %%       - A literal percent character.
	 *     %[t]     - Where [t] is a type specifier.
	 *     %[n]$[x] - Where [n] is an argument specifier and [t] is a type specifier.
	 *
	 * Types:
	 * a - Numeric: Replacement text is coerced to a numeric type but not quoted or escaped.
	 * e - Escape: Replacement text is passed to $this->escape().
	 * E - Escape (extra): Replacement text is passed to $this->escape() with true as the second argument.
	 * n - Name Quote: Replacement text is passed to $this->quoteName().
	 * q - Quote: Replacement text is passed to $this->quote().
	 * Q - Quote (no escape): Replacement text is passed to $this->quote() with false as the second argument.
	 * r - Raw: Replacement text is used as-is. (Be careful)
	 *
	 * Date Types:
	 * - Replacement text automatically quoted (use uppercase for Name Quote).
	 * - Replacement text should be a string in date format or name of a date column.
	 * y/Y - Year
	 * m/M - Month
	 * d/D - Day
	 * h/H - Hour
	 * i/I - Minute
	 * s/S - Second
	 *
	 * Invariable Types:
	 * - Takes no argument.
	 * - Argument index not incremented.
	 * t - Replacement text is the result of $this->currentTimestamp().
	 * z - Replacement text is the result of $this->nullDate(false).
	 * Z - Replacement text is the result of $this->nullDate(true).
	 *
	 * Usage:
	 * $query->format('SELECT %1$n FROM %2$n WHERE %3$n = %4$a', 'foo', '#__foo', 'bar', 1);
	 * Returns: SELECT `foo` FROM `#__foo` WHERE `bar` = 1
	 *
	 * Notes:
	 * The argument specifier is optional but recommended for clarity.
	 * The argument index used for unspecified tokens is incremented only when used.
	 *
	 * @param   string  $format  The formatting string.
	 *
	 * @return  string  Returns a string produced according to the formatting string.
	 *
	 * @since   3.1.4
	 */
	public function format($format)
	{
		$query = $this;
		$args = array_slice(func_get_args(), 1);
		array_unshift($args, null);

		$i = 1;
		$func = function ($match) use ($query, $args, &$i)
		{
			if (isset($match[6]) && $match[6] == '%')
			{
				return '%';
			}

			// No argument required, do not increment the argument index.
			switch ($match[5])
			{
				case 't':
					return $query->currentTimestamp();
					break;

				case 'z':
					return $query->nullDate(false);
					break;

				case 'Z':
					return $query->nullDate(true);
					break;
			}

			// Increment the argument index only if argument specifier not provided.
			$index = is_numeric($match[4]) ? (int) $match[4] : $i++;

			if (!$index || !isset($args[$index]))
			{
				// TODO - What to do? sprintf() throws a Warning in these cases.
				$replacement = '';
			}
			else
			{
				$replacement = $args[$index];
			}

			switch ($match[5])
			{
				case 'a':
					return 0 + $replacement;
					break;

				case 'e':
					return $query->escape($replacement);
					break;

				case 'E':
					return $query->escape($replacement, true);
					break;

				case 'n':
					return $query->quoteName($replacement);
					break;

				case 'q':
					return $query->quote($replacement);
					break;

				case 'Q':
					return $query->quote($replacement, false);
					break;

				case 'r':
					return $replacement;
					break;

				// Dates
				case 'y':
					return $query->year($query->quote($replacement));
					break;

				case 'Y':
					return $query->year($query->quoteName($replacement));
					break;

				case 'm':
					return $query->month($query->quote($replacement));
					break;

				case 'M':
					return $query->month($query->quoteName($replacement));
					break;

				case 'd':
					return $query->day($query->quote($replacement));
					break;

				case 'D':
					return $query->day($query->quoteName($replacement));
					break;

				case 'h':
					return $query->hour($query->quote($replacement));
					break;

				case 'H':
					return $query->hour($query->quoteName($replacement));
					break;

				case 'i':
					return $query->minute($query->quote($replacement));
					break;

				case 'I':
					return $query->minute($query->quoteName($replacement));
					break;

				case 's':
					return $query->second($query->quote($replacement));
					break;

				case 'S':
					return $query->second($query->quoteName($replacement));
					break;
			}

			return '';
		};

		/**
		 * Regexp to find and replace all tokens.
		 * Matched fields:
		 * 0: Full token
		 * 1: Everything following '%'
		 * 2: Everything following '%' unless '%'
		 * 3: Argument specifier and '$'
		 * 4: Argument specifier
		 * 5: Type specifier
		 * 6: '%' if full token is '%%'
		 */
		return preg_replace_callback('#%(((([\d]+)\$)?([aeEnqQryYmMdDhHiIsStzZ]))|(%))#', $func, $format);
	}

	/**
	 * Add to the current date and time.
	 * Usage:
	 * $query->select($query->dateAdd());
	 * Prefixing the interval with a - (negative sign) will cause subtraction to be used.
	 * Note: Not all drivers support all units.
	 *
	 * @param   string  $date      The db quoted string representation of the date to add to. May be date or datetime
	 * @param   string  $interval  The string representation of the appropriate number of units
	 * @param   string  $datePart  The part of the date to perform the addition on
	 *
	 * @return  string  The string with the appropriate sql for addition of dates
	 *
	 * @link    http://dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_date-add
	 * @since   3.2.0
	 */
	public function dateAdd($date, $interval, $datePart)
	{
		return 'DATE_ADD(' . $date . ', INTERVAL ' . $interval . ' ' . $datePart . ')';
	}

	/**
	 * Add a query to UNION ALL with the current query.
	 * Multiple unions each require separate statements and create an array of unions.
	 *
	 * Usage:
	 * $query->union('SELECT name FROM  #__foo')
	 *
	 * The $query attribute as an array is deprecated and will not be supported in 4.0.
	 *
	 * $query->union(array('SELECT name FROM  #__foo','SELECT name FROM  #__bar'))
	 *
	 * @param   mixed    $query     The JDatabaseQuery object or string to union.
	 * @param   boolean  $distinct  Not used - ignored.
	 * @param   string   $glue      Not used - ignored.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @see     union
	 *
	 * @since   3.2.0
	 */
	public function unionAll($query, $distinct = false, $glue = '')
	{
		$glue = ')' . PHP_EOL . 'UNION ALL (';
		$name = 'UNION ALL ()';

		if (is_array($query))
		{
			JLog::add('Query attribute as an array is deprecated.', JLog::WARNING, 'deprecated');
		}

		// Get the JDatabaseQueryElement if it does not exist
		if (is_null($this->unionAll))
		{
			$this->unionAll = new JDatabaseQueryElement($name, $query, "$glue");
		}

		// Otherwise append the second UNION.
		else
		{
			$this->unionAll->append($query);
		}

		return $this;
	}

	/**
	 * Validate arguments which are passed to selectRowNumber method and set up common variables.
	 *
	 * @param   string  $orderBy           An expression of ordering for window function.
	 * @param   string  $orderColumnAlias  An alias for new ordering column.
	 *
	 * @return  void
	 *
	 * @since   3.7.0
	 * @throws  RuntimeException
	 */
	protected function validateRowNumber($orderBy, $orderColumnAlias)
	{
		if ($this->selectRowNumber)
		{
			throw new RuntimeException("Method 'selectRowNumber' can be called only once per instance.");
		}

		$this->type = 'select';

		$this->selectRowNumber = array(
			'orderBy' => $orderBy,
			'orderColumnAlias' => $orderColumnAlias,
		);
	}

	/**
	 * Return the number of the current row.
	 *
	 * Usage:
	 * $query->select('id');
	 * $query->selectRowNumber('ordering,publish_up DESC', 'new_ordering');
	 * $query->from('#__content');
	 *
	 * @param   string  $orderBy           An expression of ordering for window function.
	 * @param   string  $orderColumnAlias  An alias for new ordering column.
	 *
	 * @return  JDatabaseQuery  Returns this object to allow chaining.
	 *
	 * @since   3.7.0
	 * @throws  RuntimeException
	 */
	public function selectRowNumber($orderBy, $orderColumnAlias)
	{
		$this->validateRowNumber($orderBy, $orderColumnAlias);
		$this->select("ROW_NUMBER() OVER (ORDER BY $orderBy) AS $orderColumnAlias");

		return $this;
	}
}
