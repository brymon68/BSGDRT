import argparse
import boto3
import os
from botocore.exceptions import ClientError


def get_client(region="us-west-2", type="ec2"):
    return boto3.client(
        type,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name=region,
    )


def analyze_security_group(security_group=None):
    if security_group:
        for ingress_rule in security_group.get("IpPermissions"):
            # check to see if port 22 is between our ToPort - FromPort or is equal to 22.
            if ingress_rule.get("FromPort") and ingress_rule.get("ToPort"):
                is_between = 22 in range(
                    ingress_rule.get("FromPort"), ingress_rule.get("FromPort")
                )
                if (
                    is_between
                    or ingress_rule.get("FromPort") == 22
                    or ingress_rule.get("ToPort") == 22
                ):
                    for cidr_block in ingress_rule.get("IpRanges"):
                        if cidr_block.get("CidrIp") == "0.0.0.0/0":
                            return security_group
                        else:
                            return None
    else:
        raise Exception("No security group provided")


def remediate(bad_sg_id, good_sg_id, instance_sec_groups, client) -> bool:
    new_sec_group_ids = [
        sec_group["GroupId"]
        for sec_group in instance_sec_groups
        if sec_group["GroupId"] != bad_sg_id
    ]
    new_sec_group_ids.append(good_sg_id)
    try:
        client.modify_instance_attribute(
            InstanceId=instance.get("InstanceId"),
            Groups=new_sec_group_ids,
        )
        return True
    except ClientError as e:
        print(e)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r",
        "--region",
        action="append",
        help="Specify a region to analyze security groups in. Multiple regions can be passed with additional region flags. ",
    )
    parser.add_argument(
        "-f",
        "--fix",
        help="Pass the 'fix' flag if you would like to replace a bad ingress rule allowing traffic on port 22 from source 0.0.0.0/0 with an existing, known good security group id",
    )
    args = parser.parse_args()
    if args.region is not None:
        for region in args.region:
            try:
                client = get_client(region=region, type="ec2")
                response = client.describe_security_groups().get("SecurityGroups")
                overly_permissive_sec_groups = [
                    analyze_security_group(securitygroup) for securitygroup in response
                ]
                for security_group in overly_permissive_sec_groups:
                    if security_group is not None:
                        bad_sg_id = security_group["GroupId"]
                        print(
                            f"Identified bad security group: {bad_sg_id} with overly permissive ingress from source: 0.0.0.0/0. Now checking to determine if bad sg is associated with any running EC2 instances"
                        )
                        if args.fix is not None:
                            instances = client.describe_instances()
                            for reservation in instances["Reservations"]:
                                for instance in reservation["Instances"]:
                                    # instance is running
                                    if instance.get("State").get("Code") == 16:
                                        instance_sec_groups = instance["SecurityGroups"]
                                        for sec_group in instance_sec_groups:
                                            if sec_group.get("GroupId") == bad_sg_id:
                                                print(
                                                    f"Bad security group {bad_sg_id} found to be associated with {instance.get('InstanceId')}"
                                                )
                                                print("Now remediating")
                                                good_sg_id = args.fix
                                                if remediate(
                                                    bad_sg_id,
                                                    good_sg_id,
                                                    instance_sec_groups,
                                                    client,
                                                ):
                                                    print(
                                                        f"Successfully removed bad security group: {bad_sg_id} has been unattached from instance: {instance.get('InstanceId')} and replaced with {args.fix}"
                                                    )
                                                else:
                                                    raise Exception(
                                                        "Unable to succesfully modify bad security group"
                                                    )

                                            else:
                                                print(
                                                    f"Bad security group is not associated with any EC2 instances"
                                                )
            except ClientError as e:
                print(e)
    else:
        raise Exception("No region argument provided")
