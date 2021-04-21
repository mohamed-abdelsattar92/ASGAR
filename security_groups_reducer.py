import argparse
from time import time

import boto3

'''
AWS Security Groups Analyzer/Reducer helps you see the overall view of your EC2 instance security groups,
which ports are open to what IP ranges.
'''
def parse_command_line_arguments():
    args_parser = argparse.ArgumentParser(description='Process script arguments')
    args_parser.add_argument('-i', '--instance-id', help='The instance id that you need to investigate its security groups')
    args_parser.add_argument('-r', '--region', help='The AWS region where the instance resides')
    args_parser.add_argument('-p', '--profile', help='The AWS named profile you wish to use with this script')
    args_parser.add_argument('-d', '--detail', help='The Details of each security group with Inbound and Outbound rules')
    return args_parser.parse_args()


def configure_boto3_session(profile_name=''):
    if profile_name:
        return boto3.session.Session(profile_name=profile_name)
    return boto3.session.Session()


def is_all_traffic_allowed(permission_entry):
    return permission_entry['IpProtocol'] == '-1'

def get_protocol(permission_entry):
    return permission_entry['IpProtocol']

def process_permission_entry(permission_entry):
    if is_all_traffic_allowed(permission_entry):
            print('All Traffic Allowed From Cidr Range: {0}'.format(permission_entry['IpRanges']))
    else:
        if (permission_entry['FromPort'] == permission_entry['ToPort']):
            ports = permission_entry['FromPort']
        else:
            ports = '{0}-{1}'.format(permission_entry['FromPort'], permission_entry['ToPort'])
        print('Protocol: {0}, Ports:{1}, Cidr Ranges:{2}'.format(permission_entry['IpProtocol'], ports, permission_entry['IpRanges']))

global_start = time()
args = parse_command_line_arguments()

instance_id = args.instance_id
region = args.region
profile = args.profile

boto3_session = configure_boto3_session(profile)

ec2_resource = boto3_session.resource('ec2', region_name=region)
aws_instance = ec2_resource.Instance(instance_id)


security_groups_list = []
for security_group in aws_instance.security_groups:
    security_groups_list.append(ec2_resource.SecurityGroup(security_group['GroupId']))

# print(security_groups_list)
# print(security_groups_list[0].ip_permissions_egress)

print('Security Analysis')
for security_group in security_groups_list:
    print('-------{0}---------\n-------{1}---------'.format(security_group.group_name, 'Inbound Rules'))
    for permission_entry in security_group.ip_permissions:
        process_permission_entry(permission_entry)
    print('-------{0}---------'.format('Outbound Rules'))
    for permission_entry in security_group.ip_permissions_egress:
        process_permission_entry(permission_entry)

global_end = time()
print('Security Groups Analyzed in {0} seconds'.format(global_end - global_start))


if __name__ == '__main__':
    print("Testing Script")
    parse_command_line_arguments()
