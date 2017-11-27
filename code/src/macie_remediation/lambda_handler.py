import json
import logging
import os

import boto3

from macie_remediation.alert import AlertNotification
from macie_remediation.remediator.s3 import RSAKeyUploadedRemediator
from macie_remediation.remediators import NoopRemediator
from macie_remediation.util.log import setup_lambda_logging

logger = logging.getLogger(__name__)

# global var, so it lives as long as Lambda container (super-basic caching)
remediators = None


class Handler:
    def __init__(self, context):
        self.context = context
        self.remediators = self._create_remediators()

    def handle(self, event):
        if event.get('detail-type') != 'Macie Alert':
            logger.error('Unknown detail-type: %s', event.get('detail-type'))
            return

        logger.info(json.dumps(event, indent=2))
        alert_notification = AlertNotification(event)

        remediator = self._find_remediator(alert_notification)
        if remediator:
            logger.info('Using remediator: %s', type(remediator))
            remediator.remediate(alert_notification)
        else:
            logger.warning('No remediator found for alert: %s', alert_notification.alert_name)

    def _find_remediator(self, alert_notification):
        for remediator in self.remediators:
            if remediator.can_remediate(alert_notification):
                return remediator

        return None

    def _create_remediators(self):
        global remediators

        if remediators is None:
            remediators = []

            # add all of the remediators (first matching will be selected to remediate an alert)
            # for example:
            # LambdaFunctionRemediator(boto3.client('lambda'), {
            #     'AWS credentials embedded inside source code': 'arn:aws:lambda:us-east-1:396252082954:function:test'
            # })

            # this remediator copies risky files to safe bucket
            safe_bucket_name = os.environ.get('SAFE_BUCKET_NAME')
            if safe_bucket_name:
                s3_client = boto3.client('s3')
                remediators.append(RSAKeyUploadedRemediator(s3_client, safe_bucket_name))

            # last one - NOOP remediator, if no other was matched
            remediators.append(NoopRemediator())

        return remediators


def main(event, context):
    setup_lambda_logging()

    handler = Handler(context)
    handler.handle(event)
