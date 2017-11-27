import logging
from abc import abstractmethod

logger = logging.getLogger(__name__)


class Remediator:
    """
    Interface for remediator.

    It decides which alerts it can handle and then provides option to handle it.
    """

    @abstractmethod
    def can_remediate(self, alert_notification):
        """
        Used to check whether given remediator can handle given alert.

        :type alert_notification: macie_remediation.alert.AlertNotification
        :rtype boolean
        """
        raise NotImplementedError()

    @abstractmethod
    def remediate(self, alert_notification):
        """
        Remediates given alert.

        :type alert_notification: macie_remediation.alert.AlertNotification
        """
        raise NotImplementedError()


class NoopRemediator(Remediator):
    """
    Remediator that does nothing.

    Used as catch-all remediator if no other remediator was found for given alert.
    """

    def can_remediate(self, alert_notification):
        return True

    def remediate(self, alert_notification):
        """
        :type alert_notification: macie_remediation.alert.AlertNotification
        :rtype boolean
        """
        logger.info('Remediator for alert "%s" wasn\'t found. Skipping...', alert_notification.alert_name)


class LambdaFunctionRemediator(Remediator):
    """
    Remediator that calls another Lambda function to remediate an alert.
    """

    def __init__(self, lambda_client, alert_to_function_mapping):
        self.lambda_client = lambda_client
        self.alert_to_function_mapping = alert_to_function_mapping

    def can_remediate(self, alert_notification):
        if alert_notification.alert_name in self.alert_to_function_mapping:
            return True

    def remediate(self, alert_notification):
        lambda_function_arn = self.alert_to_function_mapping[alert_notification.alert_name]
        self.lambda_client.invoke(
            FunctionName=lambda_function_arn,
            InvokationType='Event'
        )
