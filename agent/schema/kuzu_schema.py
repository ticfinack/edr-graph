"""Kuzu graph database DDL statements."""

NODE_TABLES = [
    """
    CREATE NODE TABLE IF NOT EXISTS User(
        id STRING,
        name STRING,
        uid STRING,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS Process(
        id STRING,
        name STRING,
        pid INT64,
        cmd_line STRING,
        exe_path STRING,
        hostname STRING,
        start_time TIMESTAMP,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS IP(
        id STRING,
        address STRING,
        is_private BOOLEAN,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS Domain(
        id STRING,
        name STRING,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        is_dga_candidate BOOLEAN,
        tld STRING,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS File(
        id STRING,
        path STRING,
        hash_sha256 STRING,
        size INT64,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS RegistryKey(
        id STRING,
        path STRING,
        value_name STRING,
        value_data STRING,
        previous_data STRING,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        PRIMARY KEY (id)
    )
    """,
]

REL_TABLES = [
    """
    CREATE REL TABLE IF NOT EXISTS SPAWNED(
        FROM User TO Process,
        timestamp TIMESTAMP,
        activity_id INT64,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS CONNECTED_TO(
        FROM Process TO IP,
        timestamp TIMESTAMP,
        dst_port INT64,
        protocol STRING,
        direction STRING,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS RESOLVED(
        FROM Process TO Domain,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS RESOLVES_TO(
        FROM Domain TO IP,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS CREATED_FILE(
        FROM Process TO File,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS MODIFIED_FILE(
        FROM Process TO File,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS READ_FILE(
        FROM Process TO File,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS DELETED_FILE(
        FROM Process TO File,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS CREATED_REG(
        FROM Process TO RegistryKey,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS MODIFIED_REG(
        FROM Process TO RegistryKey,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
    """
    CREATE REL TABLE IF NOT EXISTS DELETED_REG(
        FROM Process TO RegistryKey,
        timestamp TIMESTAMP,
        event_id INT64
    )
    """,
]

ALL_DDL = NODE_TABLES + REL_TABLES


def init_graph_schema(conn) -> None:
    """Execute all DDL statements to initialize the graph schema."""
    for ddl in ALL_DDL:
        conn.execute(ddl)
