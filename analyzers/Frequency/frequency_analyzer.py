import datetime as dt
from collections import defaultdict


class FrequencyAnalyzer:
    def __init__(self, seconds: int, hits_to_clear=1000):
        self.seconds = seconds
        self.hits_to_clear = hits_to_clear
        self.hits = 0
        self.state = defaultdict(list)

    def log(self, ip):
        self.hits += 1
        self.clear_if_hits_reached()
        self.state[ip].append(dt.datetime.now())

    def frequency(self, ip):

        clean_older_than = dt.datetime.now() - dt.timedelta(seconds=self.seconds)
        self.state[ip] = list(filter(lambda x: x > clean_older_than, self.state[ip]))
        return len(self.state[ip])

    def clear_if_hits_reached(self):
        if self.hits >= self.hits_to_clear:
            self.hits = 0
            self._full_clean()

    def _full_clean(self):
        clean_older_than = dt.datetime.now() - dt.timedelta(seconds=self.seconds)
        keys_to_drop = list()
        for key in self.state:
            self.state[key] = list(filter(lambda x: x < clean_older_than, self.state[key]))

            if len(self.state[key]) == 0:
                keys_to_drop.append(key)

        for key in keys_to_drop:
            self.state.pop(key, None)

    def __call__(self, ip):
        self.log(ip)
        return self.frequency(ip)

