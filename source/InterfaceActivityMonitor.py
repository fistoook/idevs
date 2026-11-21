import psutil

class InterfaceActivityMonitor:
    def __init__(self):
        self.stats = None

    def get_activity(self):
        stats = psutil.net_io_counters(pernic=True)
        activity = {}

        # first read
        if self.stats is None:
            self.stats = stats
            return activity

        
        for iface, data in stats.items():
            if iface in self.stats:
                activity[iface] = data.packets_recv - self.stats[iface].packets_recv

        self.stats = stats
        return activity

