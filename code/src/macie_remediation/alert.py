class AlertNotification:
    """
    Wraps raw event from CloudWatch Events.
    """
    def __init__(self, raw_event):
        self.raw_event = raw_event

        self._alert_name = self.raw_event.get('detail', {}).get('name')

    @property
    def alert_name(self):
        return self._alert_name
