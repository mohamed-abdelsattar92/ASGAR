import argparse
from time import time

import boto3

'''
AWS Security Groups Analyzer/Reducer helps you to
    - Get a report of the overall view of your EC2 instance security groups, which ports are open to what IP ranges.
    - Know which security groups are not used by any resource, so that you can safely remove them either manually or using ASGAR


Features:
1- give you a summary of the security groups that are attached to your instance or rds database
2- (if possible) analyze floating security groups and return their IDs to delete them by ID
    2.1- using the information in the following link: https://aws.amazon.com/premiumsupport/knowledge-center/ec2-find-security-group-resources/ I can get what is
        using my security group and can delete it or get some details of what is using it.
3- Use logger to log to console and file
4- filter security groups by VPC_Id

Findings:
1- when searching by instance ID the security groups returned are just the security groups attached to the primary interface.
'''
def parse_command_line_arguments():
    args_parser = argparse.ArgumentParser(description='Process script arguments')
    args_parser.add_argument('-p', '--profile', help='The AWS named profile you wish to use with this script')
    args_parser.add_argument('-r', '--region', help='The AWS region where the instance resides')
    args_parser.add_argument('-n', '--network-interface-id', help='The network interface id that you need to investigate its security groups')
    args_parser.add_argument('-d', '--detail', help='The Details of each security group with Inbound and Outbound rules')
    args_parser.add_argument('--get-unused-groups', help='A list of un-used security groups that can safely be deleted')
    args_parser.add_argument('--auto-delete-unused-groups', help='A flag to enable the automated deletion of un-used security groups, used in conjunction with --get-unused-groups param')
    return args_parser.parse_args()

def configure_boto3_session(profile_name=''):
    '''
    Configure boto3 session with the given profile name if it's given otherwise use the default session,
    which will use the environment variables
    AWS_SECRET_ACCESS_KEY
    AWS_ACCESS_KEY_ID
    AWS_SESSION_TOKEN

    Parameters:
        - profile_name: the name of the configured aws profile in the ~/.aws/credentials or ~/.aws/config files you wish to use

    Returnes:
        - Configured boto3 session ready to be used
    '''

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

# def run_in_detailed_mode():
#     pass

# def run_in_scanning_mode():
#     pass

# def run_in_automated_deletion_mode():
#     pass

def is_security_group_used(ec2_client, security_group):
    print('Testing Security Group: {0}'.format(security_group['GroupName']))
    network_interfaces = ec2_client.describe_network_interfaces(
        Filters=[
            {
                'Name': 'group-id',
                'Values': [
                    security_group['GroupId'],
                ]
            }
        ]
    )
    if network_interfaces['NetworkInterfaces']:
        return True
    return False

def get_unused_security_groups(ec2_client):
    # TODO: Validata that if the account has more than 50 security groups that they're all returned
    security_groups = ec2_client.describe_security_groups()
    print('Total Number of Security Groups = {0}'.format(len(security_groups['SecurityGroups'])))
    unused_security_groups = []
    for security_group in security_groups['SecurityGroups']:
        if not is_security_group_used(ec2_client, security_group):
            unused_security_groups.append(security_group)
    return unused_security_groups


def delete_security_group(ec2_client, group_id):
    ec2_client.delete_security_group(GroupId=group_id)

def delete_security_groups(ec2_client, group_ids):
    for group_id in group_ids:
        print('Deleting Group with Id: {0}'.format(group_id))
        delete_security_group(ec2_client, group_id)

def run():
    args = parse_command_line_arguments()
    if not args.region:
        print('Must supply a region via the --region (-r for short) argument')
        exit(0)
    boto3_session = configure_boto3_session(args.profile)
    ec2_resource = boto3_session.resource('ec2', region_name=args.region)
    ec2_client = boto3_session.client('ec2', region_name=args.region)
    if args.get_unused_groups:
        unused_security_groups = get_unused_security_groups(ec2_client)
        print('Total Number Of Un-Used Security Groups = {0}'.format(len(unused_security_groups)))
        for idx, s in enumerate(unused_security_groups):
            print('{0} - Group Name: {1} - Group Id: {2} - VPC Id: {3}'.format(idx + 1, s['GroupName'], s['GroupId'], s['VpcId']))
        exit(0)

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
