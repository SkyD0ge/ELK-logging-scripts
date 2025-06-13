import boto3
import json
from botocore.exceptions import ClientError

def copy_iam_user_permissions(source_username, target_username):
    iam = boto3.client('iam')
    user_created = False

    try:
        iam.create_user(UserName=target_username)
        user_created = True
        print(f"Created new user: {target_username}")

        # copy attached managed policies
        print("Copying managed policies...")
        attached_policies = iam.list_attached_user_policies(UserName=source_username)['AttachedPolicies']
        for policy in attached_policies:
            iam.attach_user_policy(UserName=target_username, PolicyArn=policy['PolicyArn'])
            print(f"Attached: {policy['PolicyName']}")

        # copy inline policies
        print("Copying inline policies...")
        inline_policies = iam.list_user_policies(UserName=source_username)['PolicyNames']
        for policy_name in inline_policies:
            policy_document = iam.get_user_policy(
                UserName=source_username,
                PolicyName=policy_name
            )['PolicyDocument']
            iam.put_user_policy(
                UserName=target_username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            print(f"Copied inline policy: {policy_name}")

        print(f"\nSuccessfully copied permissions from '{source_username}' to '{target_username}'")
        
        # copy group memberships
        user_groups = iam.list_groups_for_user(UserName=source_username)['Groups']
        for group in user_groups:
            iam.add_user_to_group(GroupName=group['GroupName'], UserName=target_username)
            print(f"Added to group: {group['GroupName']}")
        print(f"\nSuccessfully copied permissions from {source_username} to {target_username}")

    except ClientError as error:
        print(f"\nError: {error.response['Error']['Message']}")
        if user_created:
            try:
                iam.delete_user(UserName=target_username)
                print(f"Rolled back: deleted partially created user '{target_username}'")
            except ClientError:
                print(f"Cleanup failed for '{target_username}'")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python copy_iam_user.py <source_user> <target_user>")
        sys.exit(1)

    source_user = sys.argv[1]
    target_user = sys.argv[2]

    copy_iam_user_permissions(source_user, target_user)
