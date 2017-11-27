import logging

from macie_remediation.remediators import Remediator

logger = logging.getLogger(__name__)


class RSAKeyUploadedRemediator(Remediator):
    def __init__(self, s3_client, safe_bucket_name):
        self.s3_client = s3_client
        self.safe_bucket_name = safe_bucket_name

    def can_remediate(self, alert_notification):
        """
        :type alert_notification: macie_remediation.alert.AlertNotification
        :rtype boolean
        """
        return alert_notification.alert_name == 'RSA Private Key uploaded to AWS S3'

    def remediate(self, alert_notification):
        """
        :type alert_notification: macie_remediation.alert.AlertNotification
        """
        alert_summary = alert_notification.raw_event['detail']['summary']
        detected_objects = alert_summary.get('Object', {})
        if detected_objects:
            for key, value in detected_objects.items():
                self._copy_to_safe_bucket(key)

    def _copy_to_safe_bucket(self, key):
        logger.info('Moving object containing risky information "%s" to safe bucket: "%s"', key, self.safe_bucket_name)

        # format for objects from notification is "bucket_name/object_key", e.g. "bucket_a/a/b/c/d.txt"
        (bucket_name, object_key) = key.split('/', 1)

        if bucket_name == self.safe_bucket_name:
            logger.info('Not moving - it\'s already in safe bucket')

        copy_source = {'Bucket': bucket_name, 'Key': object_key}
        try:
            self.s3_client.copy(copy_source, self.safe_bucket_name, object_key)
            self._delete_object(bucket_name, object_key)
        except Exception:
            logger.exception('Cannot copy source object!')

    def _delete_object(self, bucket_name, object_key):
        try:
            self.s3_client.delete_object(Bucket=bucket_name, Key=object_key)
            # TODO: with current roles DeleteObject is not permitted, you need to add it when using this template
        except Exception:
            logger.exception('Cannot delete source object!')
