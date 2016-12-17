#!/usr/bin/python3

from __future__ import print_function
import base64
import httplib2
import json
import os
import re
import requests
import time
import traceback

from apiclient import discovery, errors
import oauth2client
from oauth2client import client
from oauth2client import tools

from secrets import IMGUR_CLIENT_ID
from secrets import SLACK_POST_URL

import argparse
flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()

# Expected subject tag for e-mails that contain pictures of food.
SUBJECT_TAG = '[cis-vultures-l]'

# Supported MIME types for pictures of food.
IMG_MIME_TYPES = {'image/jpeg', 'image/png'}

# Expected filename pattern for pictures of food.
# An e-mail will be ignored if it contains more than one attachment that has a
# MIME type listed above and whose name matches this regex.
IMG_ATTACHMENT_NAME_REGEX = re.compile(r"food\..*")

# Ignore messages older than this
MAX_FRESH_AGE_MINUTES = 30

SCOPES = 'https://www.googleapis.com/auth/gmail.modify'
APPLICATION_NAME = 'CIS Vultures bot'
IMGUR_UPLOAD_URL = 'https://api.imgur.com/3/image'
CLIENT_SECRET_FILE = 'client_secret.json' # Contains Google API key
GMAIL_CREDENTIALS_FILE = 'gmail-credentials.json'

def getCredentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    store = oauth2client.file.Storage(GMAIL_CREDENTIALS_FILE)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        credentials = tools.run_flow(flow, store, flags)
    return credentials

def getUnreadMessages(service):
    """Returns a list of unread messages in the inbox."""
    response = service.users().messages() \
        .list(userId='me', labelIds=['INBOX', 'UNREAD']).execute()
    messages = []
    if 'messages' in response:
        messages.extend(response['messages'])

    while 'nextPageToken' in response:
        pageToken = response['nextPageToken']
        response = service.users().messages() \
            .list(userId='me', labelIds=['INBOX', 'UNREAD'],
                pageToken=pageToken) \
            .execute()
        messages.extend(response['messages'])

    return messages

def getFoodImg(service, messageID):
    """The behaviour of this function falls into three cases:
      1. If the e-mail with the given messageID is a recently sent VultureEye
         message, then the image is extracted, the message is marked as read
         and moved to the trash, and a map is returned, containing the image's
         name and data.

      2. Otherwise, if the e-mail is an old VultureEye message, then the
         message is marked as read and moved to the trash, and None is
         returned.

      3. Otherwise, the e-mail is not a VultureEye message. The message is
         simply marked as read and None is returned.

    An e-mail is a VultureEye message if its subject starts with SUBJECT_TAG
    and exactly one of its attachments has a name matching
    IMG_ATTACHMENT_NAME_REGEX with a MIME type in IMG_MIME_TYPES.

    An e-mail is recently sent if it was received in the past
    MAX_FRESH_AGE_MINUTES minutes.
    """
    # First, mark the message as being read.
    service.users().messages().modify(userId='me', id=messageID,
        body={'removeLabelIds': ['UNREAD']}).execute()

    # Obtain the message.
    message = service.users().messages().get(userId='me', id=messageID)\
        .execute()

    # Check whether the subject has the appropriate SUBJECT_TAG.
    subject = None
    for header in message['payload']['headers']:
        if header['name'].lower() == 'subject':
            subject = header['value']
            break

    if not subject or not subject.startswith(SUBJECT_TAG):
        # Subject doesn't match.
        return None

    # Check whether the message has the appropriate attachment.
    result = None
    for part in message['payload']['parts']:
        if part['filename'] \
                and IMG_ATTACHMENT_NAME_REGEX.match(part['filename']) \
                and part['mimeType'] in IMG_MIME_TYPES:
            if result:
                # More than one image found.
                return None

            imageData = None
            if 'data' in part['body']:
                imageData = part['body']['data']
            else:
                attID = part['body']['attachmentId']
                attachment = service.users().messages().attachments() \
                    .get(userId='me', messageId=messageID, id=attID).execute()
                imageData = attachment['data']

            # Assemble result while decoding image data.
            result = {'name': part['filename'],
                'data': base64.urlsafe_b64decode(imageData.encode('UTF-8'))}

    if not result:
        return None

    # We have a VultureEye message. Move the message to the trash.
    service.users().messages().trash(userId='me', id=messageID).execute()

    # Check the message's freshness.
    messageTimestamp = int(message['internalDate'])/1000
    if time.time() - messageTimestamp > MAX_FRESH_AGE_MINUTES * 60:
        return None

    return result

def imgurUpload(imgName, imgData):
    """Uploads the given image to imgur. Returns the resulting image URL,
    paired with the URL for deleting the image.
    """
    headers = {'Authorization': 'Client-ID %s' % IMGUR_CLIENT_ID}
    payload = {'image': base64.b64encode(imgData),
        'type': 'base64', 'name': imgName}
    r = requests.post(IMGUR_UPLOAD_URL, data=payload, headers=headers)
    r = r.json()['data']
    return r['link'], ('https://imgur.com/delete/%s' % r['deletehash'])

def slackPost(imgURL, delURL):
    payload = {'payload':
            json.dumps({'text':
                'I have discovered fine dining in the 4th floor kitchen! <%s> [<%s|delete>]' \
                    % (imgURL, delURL)})}
    requests.post(SLACK_POST_URL, data=payload)

def main():
    credentials = getCredentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)

    while True:
        try:
            for msg in getUnreadMessages(service):
                img = getFoodImg(service, msg['id'])
                if img:
                    # Upload to imgur.
                    imgURL, delURL = imgurUpload(img['name'], img['data'])
                    
                    # Post to Slack.
                    slackPost(imgURL, delURL)
        except:
            traceback.print_exc()

        time.sleep(60)

if __name__ == '__main__':
    while True:
        try:
            main()
        except:
            traceback.print_exc()

        time.sleep(60)
