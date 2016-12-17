# cis-vultures-bot

This Slackbot watches a GMail inbox for e-mail from the CIS VultureEye camera,
uploads pictures from the camera to Imgur, and posts the result to the Cornell
CIS Slack.

The bot currently runs on Jed's office computer, and there are a couple of
places where the install path is hardcoded to `/home/jed/src/cis-vultures-bot`.
There are authentication secrets living in `client_secret.json`,
`gmail-credentials.json`, and `secrets.py`, which have been redacted in this
repo.
