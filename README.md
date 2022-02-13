# Bad SG detection and remediation tool (BSGDRT)


## Overview

BSGDRT can be used to detect running EC2 instances with overly permissive AWS SecurityGroups that allow ingress from the internet e.g. 0.0.0.0/0.

## Installation

1. If for some reason you dont have aws-cli tools, go grab them here:  https://awscli.amazonaws.com/AWSCLIV2.pkg 
2. Clone BSGDRT and cd into the root of the directory. 
3. ```python3 -m venv ./venv```
4. ```source ./venv/bin/activate``` 
5. ```pip install boto3```
6. Provide account credentials for an account you would like to audit:  ```aws configure```  
7. ```python run.py -h ``` 

## Command line options

* -r || --region (required) - Provide a region for a resource such as 'us-west-1'. You can provide multiple '-r' flags for a given execution 
* -f || --fix (optional) - Provide the -f flag and a SecurityGroupId and BSGDRT will attempt to replace the overly-permissive security group with the security group corresponding to the user-provided SecurityGroupId.  
* -h (help)

## Example

```python run.py -r us-west-1 -f sg-09852322222b03b914```

## Example output: 

```
Identified bad security group: sg-00c37308445098010 with overly permissive ingress from source: 0.0.0.0/0. Now checking to determine if bad sg is associated with any running EC2 instances
Bad security group is not associated with any EC2 instances
Identified bad security group: sg-0985a42c06b03b914 with overly permissive ingress from source: 0.0.0.0/0. Now checking to determine if bad sg is associated with any running EC2 instances
Bad security group sg-0985a42c06b03b914 found to be associated with i-08cde1c94d55a06be
Now remediating
Successfully removed bad security group: sg-0985a42c06b03b914 has been unattached from instance: i-08cde1c94d55a06be and replaced with sg-0985a42c06b03b914

```
