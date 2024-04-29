import argparse
import logging
import boto3
from config import AWS_SERVICES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def is_valid_region(region: str) -> bool:
    """
    Check if the provided AWS region is valid.

    Args:
        region (str): The AWS region to be validated.

    Returns:
        bool: True if the region is valid, False otherwise.
    """
    session = boto3.Session()
    available_regions = session.get_available_regions('ec2')  # Choose any service
    return region in available_regions


def list_resources(service_name: str, region: str):
    """
    List resources from the specified AWS service in the given region.

    Args:
        service_name (str): The name of the AWS service.
        region (str): The AWS region to list resources from.

    Raises:
        ValueError: If the provided service name is invalid.
        Exception: If any other error occurs during execution.
    """
    try:
        service_client = boto3.client(service_name.lower(), region)
        service_details = AWS_SERVICES.get(service_name.lower())
        if not service_details:
            raise ValueError('The given service name does not exist')
        function_name = service_details['function']
        operation_name = service_details['operation']
        response = getattr(service_client, function_name)()
        result = eval(operation_name)
        return result
    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")


def main():
    """
    Main function to parse command-line arguments and execute the script.
    """
    parser = argparse.ArgumentParser(description="List resources from AWS services.")
    parser.add_argument("service_name", help="Name of the AWS service")
    parser.add_argument("region", help="Region to list resources from")
    args = parser.parse_args()

    service_name = args.service_name
    region = args.region

    if not is_valid_region(region):
        logger.error(f"Invalid region: {region}")
        return

    result = list_resources(service_name, region)
    if result is not None:
        for item in result:
            print(item)


if __name__ == "__main__":
    main()
