# AWS Resource Listing Script

This script lists resources from AWS services based on the provided service name and region.

## Usage

To run the script, use the following command:

``` bash 
python script.py <service_name> <region>
```


## Dependencies
The script has been written in python 3
This is using aws profile credentials set to default
The script requires the following dependencies:

- `boto3`: The AWS SDK for Python.
- `argparse`: The command line argument parser

These dependencies can be installed via pip:

``` bash 
python list_aws_resources.py -h
```
To get details about the script