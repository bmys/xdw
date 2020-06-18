from abc import ABC, abstractmethod


class DbInterface(ABC):

    @abstractmethod
    def get_by_id(self, key):
        pass

    @abstractmethod
    def get_all_suspects(self):
        pass

    @abstractmethod
    def confirm_case(self, key, name='unknown'):
        pass
