import yaml
from pyspark.sql import types as ST
import ade.utils.spark_utils as su
from ade.utils.constants import types as T
from ade.utils.constants import metadata as M

CATALOG = "ade_chn_{main_env}_{layer}"
SILVER_LAYER = "silver"
TECHNICAL_STAGE = "technical"
BASE_DIR_CONTAINERS = ("transient", "curated")


def resolve_catalog(layer: str) -> str:
    main_env = su.get_main_env()
    return CATALOG.format(main_env=main_env, layer=layer)


def resolve_base_dir(env: str, content: str) -> str:
    main_env = su.get_main_env()
    storage_account = su.get_storage_account(main_env)

    for container in BASE_DIR_CONTAINERS:
        base_dir = su.BASE_DIR.format(
            container=container,
            storage_account=storage_account,
        )
        content = content.replace(f"{{{{base_dir}}}}/{container}", base_dir)

    return content.replace("{{env}}", env)


def get_artifact_base_path(env: str, artifact_type: str = "metadata") -> str:
    """Return the artifact folder deployed for an environment."""

    volume_base_path = "/Volumes/{catalog}/artifacts/{artifact_type}/{folder_env}"
    volume_path = volume_base_path.format(
        catalog=resolve_catalog(layer="bronze"),
        artifact_type=artifact_type,
        folder_env=env,
    )
    if su.does_path_exist_in_databricks(volume_path):
        return volume_path
    raise FileNotFoundError(
        f"The '{artifact_type}' artifacts for env '{env}' were not found "
        f"under '{volume_path}'."
    )

def read_artifacts_file(env: str, artifact_path: str) -> dict:
    with open(artifact_path, encoding="utf-8") as artifact_file:
        content = artifact_file.read()
    return yaml.safe_load(resolve_base_dir(env, content))


def get_source_metadata(env: str, source: str, entity: str) -> dict:
    base_path = get_artifact_base_path(env)
    artifact_path = f"{base_path}/source/{source}/{entity}.yml"
    return read_artifacts_file(env, artifact_path)


def get_technical_metadata(env: str, base: str, entity: str) -> dict:
    base_path = get_artifact_base_path(env)
    artifact_path = f"{base_path}/technical/{base}/{entity}.yml"
    return read_artifacts_file(env, artifact_path)


def build_schema_name(env: str, stage: str, base_name: str) -> str:
    return f"{env}_{stage}_{base_name}"


def build_full_table_name(catalog: str, schema: str, entity: str) -> str:
    return f"{catalog}.{schema}.{entity}"


def get_table_identifier(
    layer: str,
    env: str,
    stage: str,
    base: str,
    entity: str,
) -> str:
    catalog = resolve_catalog(layer)
    schema = build_schema_name(env=env, stage=stage, base_name=base)
    return build_full_table_name(catalog, schema, entity)


def get_technical_table_identifier_from_metadata(metadata: dict, env: str) -> str:
    return get_table_identifier(
        layer=SILVER_LAYER,
        env=env,
        stage=TECHNICAL_STAGE,
        base=metadata["base"],
        entity=metadata["entity"],
    )


def get_or_create_volume_location_from_metadata(
    env: str,
    metadata: dict,
    sub_folder: str,
    stage: str="raw",
):
    catalog = resolve_catalog(layer="bronze")
    source = metadata["source"]
    entity = metadata["entity"]
    schema = build_schema_name(
        env=env,
        stage=stage,
        base_name=source
    )
    return su.get_or_create_volume_location(
        catalog=catalog,
        schema=schema,
        entity=entity,
        sub_folder=sub_folder
    )

def generate_spark_schema_from_columns(columns):
    def get_column(column):
        return ST.StructField(
            name=column[M.NAME],
            dataType=get_data_type(column[M.DATA_TYPE], column),
            nullable=column.get(M.NULLABLE, True),
            metadata=column.get(M.METADATA, {}),
        )

    def get_data_type(data_type, column):
        if data_type == T.BOOLEAN:
            return ST.BooleanType()
        if data_type in [T.BYTE, T.TINYINT]:
            return ST.ByteType()
        if data_type in [T.SHORT, T.SMALLINT]:
            return ST.ShortType()
        if data_type in [T.INT, T.INTEGER]:
            return ST.IntegerType()
        if data_type in [T.LONG, T.BIGINT]:
            return ST.LongType()
        if data_type in [T.FLOAT, T.REAL]:
            return ST.FloatType()
        if data_type == T.DOUBLE:
            return ST.DoubleType()
        if data_type == T.DATE:
            return ST.DateType()
        if data_type == T.TIMESTAMP:
            return ST.TimestampType()
        if data_type == T.STRING:
            return ST.StringType()
        if data_type == T.BINARY:
            return ST.BinaryType()
        if data_type in [T.DECIMAL, T.DEC, T.NUMERIC]:
            return ST.DecimalType()
        if data_type == T.STRUCT:
            return generate_spark_schema_from_columns(column[M.INNER_COLUMNS])
        if data_type == T.ARRAY:
            return ST.ArrayType(get_data_type(column[M.SUB_TYPE], column))
        if data_type == T.STRING_ARRAY:
            return ST.ArrayType(ST.StringType())

        raise ValueError(f"Unsupported data type: {data_type}")

    return ST.StructType([get_column(c) for c in columns])
