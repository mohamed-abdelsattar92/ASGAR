import argparse
from time import time

import boto3

'''
AWS Security Groups Analyzer/Reducer helps you see the overall view of your EC2 instance security groups,
which ports are open to what IP ranges.

Features:
1- give you a summary of the security groups that are attached to your instance or rds database
2- (if possible) analyze floating security groups and return their IDs to delete them by ID
    2.1- using the information in the following link: https://aws.amazon.com/premiumsupport/knowledge-center/ec2-find-security-group-resources/ I can get what is
        using my security group and can delete it or get some details of what is using it.

Findings:
1- when searching by instance ID the security groups returned are just the security groups attached to the primary interface.
'''
def parse_command_line_arguments():
    args_parser = argparse.ArgumentParser(description='Process script arguments')
    args_parser.add_argument('-n', '--network-interface-id', help='The network interface id that you need to investigate its security groups')
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

def get_security_groups_ids(ec2_resource, network_interface_id):
    network_interface = ec2_resource.NetworkInterface(network_interface_id)
    return [sg['GroupId'] for sg in network_interface.groups]

def process_permission_entry(permission_entry):
    if is_all_traffic_allowed(permission_entry):
            print('All Traffic Allowed From Cidr Range: {0}'.format(permission_entry['IpRanges']))
    else:
        if (permission_entry['FromPort'] == permission_entry['ToPort']):
            ports = permission_entry['FromPort']
        else:
            ports = '{0}-{1}'.format(permission_entry['FromPort'], permission_entry['ToPort'])
        print('Protocol: {0}, Ports:{1}, Cidr Ranges:{2}'.format(permission_entry['IpProtocol'], ports, permission_entry['IpRanges']))

def run():
    args = parse_command_line_arguments()

    boto3_session = configure_boto3_session(args.profile)
    ec2_resource = boto3_session.resource('ec2', region_name=args.region)

    security_groups_list = []
    for security_group_id in get_security_groups_ids(ec2_resource, args.network_interface_id):
        security_groups_list.append(ec2_resource.SecurityGroup(security_group_id))

    print('Security Groups Analysis')
    for security_group in security_groups_list:
        print('-------{0}---------\n-------{1}---------'.format(security_group.group_name, 'Inbound Rules'))
        for permission_entry in security_group.ip_permissions:
            process_permission_entry(permission_entry)
        print('-------{0}---------'.format('Outbound Rules'))
        for permission_entry in security_group.ip_permissions_egress:
            process_permission_entry(permission_entry)

if __name__ == '__main__':
    start_time = time()
    run()
    end_time = time()
    print('Security Groups Analyzed in {0} seconds'.format(end_time - start_time))
