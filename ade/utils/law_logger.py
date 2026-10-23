"""Log Databricks job executions to LAW and a Delta table.

``env`` is the environment requested by the job (``dev``, ``tom``, etc.).
``main_env`` is the physical Azure and Databricks environment detected at runtime.
"""

from __future__ import annotations

import base64
import datetime as dt
import functools
import hashlib
import hmac
import json
import logging
import math
import os
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

import requests
from requests import Response
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    HTTPError,
    RequestException,
    Timeout,
)

from ade.utils.python_logger import get_logger


LAW_LOG_TYPE = os.getenv("ADE_LAW_LOG_TYPE", "dbw_ade_logs")
LAW_RETRY_COUNT = 3
LAW_RETRY_INTERVAL = 1.0
LAW_REQUEST_TIMEOUT = (5.0, 15.0)

LOG_METADATA_BASE = "common"
LOG_METADATA_ENTITY = "databricks_job_log_v1"

INFO = "INFO"
WARNING = "WARNING"
ERROR = "ERROR"
DEBUG = "DEBUG"

PYTHON_LOG_LEVELS = {
    INFO: logging.INFO,
    WARNING: logging.WARNING,
    ERROR: logging.ERROR,
    DEBUG: logging.DEBUG,
}
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
SENSITIVE_KEYS = re.compile(
    r"password|secret|credential|authorization|api[_-]?key|token|"
    r"connection[_-]?string|shared[_-]?access[_-]?signature",
    re.IGNORECASE,
)
INLINE_SECRET = re.compile(
    r"(?i)(password|secret|credential|api[_-]?key|token)"
    r"(\s*[:=]\s*)[^,;\s]+"
)
BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
UNITY_CATALOG_NAME = re.compile(r"^[a-z][a-z0-9_]*$")

__all__ = ["DatabricksLogger", "databricks_logger"]


python_logger = get_logger(__name__)
Result = TypeVar("Result")


def redact_text(value: str) -> str:
    """Remove common inline secrets from a string."""

    value = BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    return INLINE_SECRET.sub(r"\1\2[REDACTED]", value)


def sanitize(value: Any, depth: int = 0) -> Any:
    """Return a redacted value that can be serialized as JSON."""

    if depth >= 6:
        return "[MAX_DEPTH]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if SENSITIVE_KEYS.search(str(key))
                else sanitize(item, depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize(item, depth + 1) for item in value]
    return redact_text(str(value))


def require_text(name: str, value: str) -> str:
    """Validate a required string."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def require_catalog_name(name: str, value: str) -> str:
    """Validate one unquoted Unity Catalog name segment."""

    value = require_text(name, value)
    if not UNITY_CATALOG_NAME.fullmatch(value):
        raise ValueError(
            f"{name} must start with a lowercase letter and contain only "
            "lowercase letters, numbers, or _"
        )
    return value


def retry_delay(response: Response | None, attempt: int) -> float:
    """Use the server delay when available, otherwise exponential backoff."""

    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return float(retry_after)
    return LAW_RETRY_INTERVAL * (2**attempt)


def post_with_retry(url: str, body: bytes, headers: Mapping[str, str]) -> None:
    """Post a LAW payload and retry temporary failures."""

    last_error: RequestException | None = None

    for attempt in range(LAW_RETRY_COUNT):
        response: Response | None = None
        try:
            response = requests.post(
                url,
                data=body,
                headers=dict(headers),
                timeout=LAW_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return
        except HTTPError as error:
            last_error = error
            if response is None or response.status_code not in RETRYABLE_STATUS_CODES:
                raise
        except (RequestsConnectionError, Timeout) as error:
            last_error = error
        except RequestException:
            raise

        if attempt < LAW_RETRY_COUNT - 1:
            time.sleep(retry_delay(response, attempt))

    if last_error is not None:
        raise last_error


class LAWLogger:
    """Send JSON events to an Azure Log Analytics workspace."""

    METHOD = "POST"
    CONTENT_TYPE = "application/json"
    RESOURCE = "/api/logs"
    API_VERSION = "2016-04-01"

    def __init__(self, law_id: str, law_secret: str) -> None:
        self.law_id = require_text("law_id", law_id)
        self.law_secret = require_text("law_secret", law_secret)

        try:
            base64.b64decode(self.law_secret, validate=True)
        except ValueError as error:
            raise ValueError("law_secret must be a valid base64 value") from error

    @staticmethod
    def build_signature(
        law_id: str,
        law_secret: str,
        request_date: str,
        content_length: int,
    ) -> str:
        """Build the SharedKey authorization header expected by LAW."""

        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{request_date}\n/api/logs"
        )
        digest = hmac.new(
            base64.b64decode(law_secret),
            string_to_hash.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        encoded_hash = base64.b64encode(digest).decode("ascii")
        return f"SharedKey {law_id}:{encoded_hash}"

    def post(self, event: Mapping[str, Any]) -> None:
        """Send one event to LAW."""

        if not isinstance(event, Mapping):
            raise TypeError("event must be a mapping")

        body = json.dumps(
            sanitize(event),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request_date = dt.datetime.now(dt.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = self.build_signature(
            law_id=self.law_id,
            law_secret=self.law_secret,
            request_date=request_date,
            content_length=len(body),
        )
        url = (
            f"https://{self.law_id}.ods.opinsights.azure.com"
            f"{self.RESOURCE}?api-version={self.API_VERSION}"
        )
        headers = {
            "Authorization": signature,
            "Content-Type": self.CONTENT_TYPE,
            "Log-Type": LAW_LOG_TYPE,
            "x-ms-date": request_date,
        }
        post_with_retry(url=url, body=body, headers=headers)


class DatabricksLogger(LAWLogger):
    """Job logger configured from the current Databricks workspace."""

    def __init__(
        self,
        law_id: str,
        law_secret: str,
        env: str,
        main_env: str,
    ) -> None:
        super().__init__(law_id=law_id, law_secret=law_secret)
        self.env = require_catalog_name("env", env)
        self.main_env = require_catalog_name("main_env", main_env)
        self.log_metadata: dict[str, Any] | None = None
        self.delta_table_identifier: str | None = None

    @classmethod
    def init_logger(cls, env: str) -> "DatabricksLogger":
        """Configure a job logger from the physical Databricks environment."""

        env = require_catalog_name("env", env)
        try:
            from ade.utils import spark_utils

            main_env = spark_utils.get_main_env()
            law_id = spark_utils.get_law_id(main_env)
            law_secret = spark_utils.get_law_secret(main_env)
        except Exception as error:  # pylint: disable=broad-exception-caught
            raise RuntimeError(
                "Unable to load LAW credentials from the Databricks secret scope"
            ) from error

        return cls(
            law_id=law_id,
            law_secret=law_secret,
            env=env,
            main_env=main_env,
        )

    def format_event(
        self,
        file_name: str,
        job_name: str,
        level: str,
        message: str,
        additional_params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build one event with job and environment context."""

        level = level.upper()
        if level not in PYTHON_LOG_LEVELS:
            raise ValueError(f"Unsupported log level: {level}")

        params = sanitize(dict(additional_params or {}))
        log_date = dt.datetime.now(dt.timezone.utc)
        return {
            "log_date": log_date,
            "level": level,
            "message": sanitize(str(message)),
            "job": require_text("job_name", job_name),
            "env": self.env,
            "main_env": self.main_env,
            "source": params.get("source"),
            "entity": params.get("entity"),
            "additional_info": json.dumps(params, ensure_ascii=False),
            "file_name": require_text("file_name", file_name),
            "year": log_date.year,
        }

    def get_log_metadata(self) -> dict[str, Any]:
        """Load the Delta log metadata once for this logger."""

        if self.log_metadata is None:
            from ade.utils.elt import common as elt_common

            self.log_metadata = elt_common.get_technical_metadata(
                env=self.env,
                base=LOG_METADATA_BASE,
                entity=LOG_METADATA_ENTITY,
            )
        return self.log_metadata

    def get_delta_table_identifier(self) -> str:
        """Return the Delta table identifier defined by the log metadata."""

        if self.delta_table_identifier is None:
            from ade.utils.elt import common as elt_common

            self.delta_table_identifier = (
                elt_common.get_technical_table_identifier_from_metadata(
                    metadata=self.get_log_metadata(),
                    env=self.env,
                )
            )
        return self.delta_table_identifier

    def write_delta(self, event: Mapping[str, Any]) -> None:
        """Append one event to the Delta log table."""

        from ade.utils import spark_utils
        from ade.utils.elt import common as elt_common

        log_date = event.get("log_date")
        if not isinstance(log_date, dt.datetime):
            raise TypeError("event log_date must be a datetime")

        metadata = self.get_log_metadata()
        schema_metadata = metadata["schema"]
        schema = elt_common.generate_spark_schema_from_columns(
            schema_metadata["columns"]
        )
        partitions = list(schema_metadata.get("partitions", []))
        delta_event = dict(event)
        delta_event["year"] = log_date.year
        dataframe = spark_utils.spark.createDataFrame(
            [delta_event],
            schema=schema,
        )
        spark_utils.write_delta_table(
            dataframe=dataframe,
            table_identifier=self.get_delta_table_identifier(),
            partitions=partitions,
        )

    def log(
        self,
        file_name: str,
        job_name: str,
        level: str,
        message: str,
        additional_params: Mapping[str, Any] | None = None,
    ) -> None:
        """Write one message to the Python logger, LAW, and Delta."""

        event = self.format_event(
            file_name=file_name,
            job_name=job_name,
            level=level,
            message=message,
            additional_params=additional_params,
        )
        python_logger.log(
            PYTHON_LOG_LEVELS[event["level"]],
            "%s. Additional info: %s",
            event["message"],
            event["additional_info"],
        )
        for destination, writer in (
            ("LAW", self.post),
            ("Delta", self.write_delta),
        ):
            try:
                writer(event)
            except Exception as error:  # pylint: disable=broad-exception-caught
                python_logger.warning(
                    "%s logging failed; the job continues (%s)",
                    destination,
                    type(error).__name__,
                )


def log_safely(
    logger: DatabricksLogger,
    file_name: str,
    job_name: str,
    level: str,
    message: str,
    additional_params: Mapping[str, Any],
) -> None:
    """Log without replacing the result or exception of the job."""

    try:
        logger.log(
            file_name=file_name,
            job_name=job_name,
            level=level,
            message=message,
            additional_params=additional_params,
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        python_logger.warning(
            "Job logging failed; the job continues (%s)",
            type(error).__name__,
        )


def databricks_logger(
    logger: DatabricksLogger,
    job_name: str,
    additional_params: Mapping[str, Any],
    file_name: str,
) -> Callable[[Callable[..., Result]], Callable[..., Result]]:
    """Decorate a job with start, success, and failure events."""

    job_name = require_text("job_name", job_name)
    file_name = require_text("file_name", file_name)
    job_params = dict(additional_params)

    def decorator(function: Callable[..., Result]) -> Callable[..., Result]:
        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Result:
            started_at = time.monotonic()
            log_safely(
                logger=logger,
                file_name=file_name,
                job_name=job_name,
                level=INFO,
                message=f"Job {job_name} started.",
                additional_params=job_params,
            )

            try:
                result = function(*args, **kwargs)
            except Exception as job_error:
                log_safely(
                    logger=logger,
                    file_name=file_name,
                    job_name=job_name,
                    level=ERROR,
                    message=f"Job {job_name} failed: {job_error}",
                    additional_params=job_params,
                )
                raise

            duration = round(time.monotonic() - started_at, 3)
            log_safely(
                logger=logger,
                file_name=file_name,
                job_name=job_name,
                level=INFO,
                message=f"Job {job_name} finished in {duration}s.",
                additional_params=job_params,
            )
            return result

        return wrapper

    return decorator
