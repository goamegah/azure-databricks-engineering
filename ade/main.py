"""Main entry point for the MDS job execution.
This module is responsible for parsing command line arguments,
importing the specified job module, and executing its main function.
It handles the dynamic import of job modules and passes the necessary arguments
to the job's main function.
"""
# ade/main.py

import sys
from importlib import import_module

from ade.utils.args_helper import parse_args, parse_bool, snake_case
from ade.utils.law_logger import DatabricksLogger, databricks_logger
from ade.utils.python_logger import get_logger

JOB_PARAM = "job"
NO_LOG_PARAM = "no_log"
ENV_PARAM = "env"
python_logger = get_logger(__name__)


def main() -> None:
    """
    Main function to execute the job specified in the command line arguments.
    It imports the job module dynamically and calls its main function with the provided arguments.
    """
    # Parse command line arguments
    args_dict = parse_args(sys.argv[1:])
    job = args_dict.pop(JOB_PARAM)
    mod = import_module(job)
    fun = getattr(mod, "main")
    args_dict[ENV_PARAM] = snake_case(args_dict[ENV_PARAM])
    no_log = parse_bool(args_dict.pop(NO_LOG_PARAM, False))

    # Execute job using the other passed arguments
    if no_log:
        # Some operations may need to run before the logging infrastructure exists.
        fun(**args_dict)
        return

    try:
        logger = DatabricksLogger.init_logger(env=args_dict[ENV_PARAM])
    except Exception as error:  # pylint: disable=broad-exception-caught
        python_logger.warning(
            "Job logging initialization failed; the job continues (%s)",
            type(error).__name__,
        )
        fun(**args_dict)
        return

    databricks_logger(
        logger=logger,
        job_name=job,
        additional_params=args_dict,
        file_name=getattr(mod, "__file__", __file__),
    )(fun)(**args_dict)
