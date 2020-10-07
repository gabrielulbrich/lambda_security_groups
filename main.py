'''
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

# Ports your application uses that need inbound permissions from the service for
# If all you're doing is HTTPS, this can be simply { 'https': 443 }
INGRESS_PORTS = {'http': 80, 'https': 443}
# Tags which identify the security groups you want to update
# For a group to be updated it will need to have 3 properties that are true:
# 1. It has to be tagged 'Protocol: X' (Where 'X' is one of your INGRESS_PORTS above)
# 2. It has to be tagged 'Name: cloudfront_g' or 'Name: cloudfront_r'
# 3. It has to be tagged 'AutoUpdate: true'
# 4. It has to be tagged 'EvenOrOdd: X' (Where 'X' is `even` or `odd`)
# If any of these 3 are not true, the security group will be unmodified.
GLOBAL_SG_TAGS = {'Name': 'cloudfront_g', 'AutoUpdate': 'true'}
REGION_SG_TAGS = {'Name': 'cloudfront_r', 'AutoUpdate': 'true'}

import boto3
import hashlib
import json
import logging
import urllib.request, urllib.error, urllib.parse
import os

import base64
import os

'''
FUNCTIONS FOR CREATING AND SEND EMAIL MESSAGE
'''

# import parsing modules
import httplib2
import html2text

# import gmail modules
from googleapiclient import errors, discovery
from oauth2client import client, tools, file

# import email modules
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mimetypes
from email.mime.image import MIMEImage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase

sender_email = "lambdatrigger@gmail.com"
receiver_email = "gabriel_ulbrich@outlook.com"
subject = "LAMBDA SNS TRIGGER"

SCOPES = 'https://www.googleapis.com/auth/gmail.send'

# store the below in the working directory
CLIENT_SECRET_FILE = 'client_secret.json'

'''
FUNCTIONS FOR CREATING AND SEND EMAIL MESSAGE
'''


def lambda_handler(event, context):
    # Set up logging
    if len(logging.getLogger().handlers) > 0:
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.DEBUG)

    # Set the environment variable DEBUG to 'true' if you want verbose debug details in CloudWatch Logs.
    try:
        if os.environ['DEBUG'] == 'true':
            logging.getLogger().setLevel(logging.INFO)
    except KeyError:
        pass

    # If you want a different service, set the SERVICE environment variable.
    # It defaults to CLOUDFRONT. Using 'jq' and 'curl' get the list of possible
    # services like this:
    # curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' ip-ranges.json | sort -u 
    SERVICE = os.getenv('SERVICE', "CLOUDFRONT")

    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # Extract the service ranges
    global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")

    # Update the security groups
    result = update_security_groups(global_cf_ranges, "GLOBAL")
    result = result + update_security_groups(region_cf_ranges, "REGION")

    SendMessage(sender_email, receiver_email, subject, msgHtml=COMBINED_HTML_MESSAGE,
                msgPlain=html_to_plain_text(COMBINED_HTML_MESSAGE))

    return result


def get_ip_groups_json(url, expected_hash):
    logging.debug("Updating from " + url)

    response = urllib.request.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json


def get_ranges_for_service(ranges, service, subset):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service and ((subset == prefix['region'] and subset == "GLOBAL") or (
                subset != 'GLOBAL' and prefix['region'] != 'GLOBAL')):
            logging.info(('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix']))
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges


def update_security_groups(new_ranges, rangeType):
    client = boto3.client('ec2')
    result = list()

    # All the security groups we will need to find.
    allSGs = INGRESS_PORTS.keys()
    allTypes = ['even', 'odd']
    # Iterate over every group, doing its global and regional versions

    for curGroup in allSGs:
        for curType in allTypes:
            tagToFind = {}
            if rangeType == "GLOBAL":
                tagToFind = GLOBAL_SG_TAGS
            else:
                tagToFind = REGION_SG_TAGS
            tagToFind['Protocol'] = curGroup
            tagToFind['EvenOrOdd'] = curType
            rangeToUpdate = get_security_groups_for_update(client, tagToFind)
            msg = 'tagged Name: {}, Protocol: {} to update'.format(tagToFind["Name"], curGroup)
            logging.info('Found {} groups {}'.format(str(len(rangeToUpdate)), msg))

            if len(rangeToUpdate) == 0:
                result.append('No groups {}'.format(msg))
                logging.warning('No groups {}'.format(msg))
            else:
                if update_security_group(client, rangeToUpdate[0], new_ranges, INGRESS_PORTS[curGroup], curType):
                    result.append('Security Group {} updated.'.format(rangeToUpdate[0]['GroupId']))
                else:
                    result.append('Security Group {} unchanged.'.format(rangeToUpdate[0]['GroupId']))

    return result


def update_security_group(client, group, new_ranges, port, even_odd):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['FromPort'] <= port and permission['ToPort'] >= port:
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        logging.debug((group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort'])))

                x = 0
                for range in new_ranges:
                    x += 1
                    if (even_odd == "even" and ((x % 2) == 0)) or (even_odd == "odd" and ((x % 2) == 1)):
                        if old_prefixes.count(range) == 0:
                            to_add.append({'CidrIp': range})
                            logging.debug((group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort'])))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        to_add = list()
        x = 0
        for range in new_ranges:
            x += 1
            if (even_odd == "even" and ((x % 2) == 0)) or (even_odd == "odd" and ((x % 2) == 1)):
                to_add.append({'CidrIp': range})
                logging.info((group['GroupId'] + ": Adding " + range + ":" + str(port)))

        permission = {'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add)

    logging.debug((group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed)))
    return (added > 0 or removed > 0)


def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)


def add_permissions(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)


def get_security_groups_for_update(client, security_group_tag):
    filters = list()
    for key, value in security_group_tag.items():
        filters.extend(
            [
                {'Name': "tag-key", 'Values': [key]},
                {'Name': "tag-value", 'Values': [value]}
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

def get_credentials():
    wd = os.getcwd()

    # creates credentials with a refresh token
    credential_path = os.path.join(wd,
                                   'credentials.json')
    store = file.Storage(credential_path)
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
        creds = tools.run_flow(flow, store)
    return creds


def SendMessage(sender, to, subject, msgHtml, msgPlain, attachmentFile=None):
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    if attachmentFile:
        message1 = createMessageWithAttachment(sender, to, subject, msgHtml, msgPlain, attachmentFile)
    else:
        message1 = CreateMessageHtml(sender, to, subject, msgHtml, msgPlain)
    result = SendMessageInternal(service, "me", message1)
    return result


def SendMessageInternal(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
        print('Message Id: %s' % message['id'])
        return message
    except errors.HttpError as error:
        print('An error occurred: %s' % error)
        return "Error"
    return "OK"


def CreateMessageHtml(sender, to, subject, msgHtml, msgPlain):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to
    print(to)
    msg.attach(MIMEText(msgPlain, 'plain'))
    msg.attach(MIMEText(msgHtml, 'html'))
    return {'raw': base64.urlsafe_b64encode(msg.as_string().encode('UTF-8')).decode('ascii')}


def createMessageWithAttachment(
        sender, to, subject, msgHtml, msgPlain, attachmentFile):
    """Create a message for an email.
    Args:
      sender: Email address of the sender.
      to: Email address of the receiver.
      subject: The subject of the email message.
      msgHtml: Html message to be sent
      msgPlain: Alternative plain text message for older email clients
      attachmentFile: The path to the file to be attached.
    Returns:
      An object containing a base64url encoded email object.
    """
    message = MIMEMultipart('mixed')
    message['to'] = to
    print(to)
    message['from'] = sender
    message['subject'] = subject

    messageA = MIMEMultipart('alternative')
    messageR = MIMEMultipart('related')

    messageR.attach(MIMEText(msgHtml, 'html'))
    messageA.attach(MIMEText(msgPlain, 'plain'))
    messageA.attach(messageR)

    message.attach(messageA)

    print("create_message_with_attachment: file: %s" % attachmentFile)
    content_type, encoding = mimetypes.guess_type(attachmentFile)

    if content_type is None or encoding is not None:
        content_type = 'application/octet-stream'
    main_type, sub_type = content_type.split('/', 1)
    if main_type == 'text':
        fp = open(attachmentFile, 'rb')
        msg = MIMEText(fp.read(), _subtype=sub_type)
        fp.close()
    elif main_type == 'image':
        fp = open(attachmentFile, 'rb')
        msg = MIMEImage(fp.read(), _subtype=sub_type)
        fp.close()
    elif main_type == 'audio':
        fp = open(attachmentFile, 'rb')
        msg = MIMEAudio(fp.read(), _subtype=sub_type)
        fp.close()
    else:
        fp = open(attachmentFile, 'rb')
        msg = MIMEBase(main_type, sub_type)
        msg.set_payload(fp.read())
        fp.close()
    filename = os.path.basename(attachmentFile)
    msg.add_header('Content-Disposition', 'attachment', filename=filename)
    message.attach(msg)

    return {'raw': base64.urlsafe_b64encode(msg.as_string().encode('UTF-8')).decode('ascii')}


'''
END EMAIL FUNCTIONS
'''

COMBINED_HTML_MESSAGE = """\
<html>
      <body>
        Sending email via a Python script via Gmail OAuth
      </body>
</html>
"""


def html_to_plain_text(html):
    plain = html2text.html2text(html)
    return plain


'''
BELOW BEGINS THE SET UP FOR SENDING AN EMAIL
'''

# This is a handy test event you can use when testing your lambda function.
'''
Sample Event From SNS:
{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"45be1ba64fe83acb7ef247bccbc45704\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}
'''