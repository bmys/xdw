import datetime
import sqlite3

class Suspicion:
    def __init__(self, id, event, time, ip, protocol):
        self.id = id
        self.event = event
        self.time = time
        self.ip = ip
        self.protocol = protocol

    @staticmethod
    def insertable(event, time, ip, protocol):
        return Suspicion(None, event, time, ip, protocol)

    def __str__(self):
        return '{}) attack_type: {}, time, {}, ip: {} protocol: {}'.format(
            self.id,
            self.event,
            self.time,
            self.ip,
            self.protocol
        )


class SuspicionModel:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def from_file(path: str):
        connection = sqlite3.connect(path, isolation_level=None)
        return SuspicionModel(connection)

    def all(self, show_handled=False):
        cursor = self.connection.cursor()

        sql = "SELECT * FROM suspicion"

        if not show_handled:
            sql = sql + " WHERE suspicion_id NOT IN (SELECT suspicion_id FROM filter_rule)"

        return [
            SuspicionModel.to_suspition(row) for row in cursor.execute(sql)
        ]

    def by_id(self, id: int):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM suspicion WHERE suspicion_id = ?", (id,))
        row = cursor.fetchone()
        return SuspicionModel.to_suspition(row)

    def create(self, suspicion: Suspicion) -> int:
        sql = """INSERT INTO suspicion (event, time, suspicious_ip, protocol)
         VALUES (?, ?, ?, ?)"""

        values = (
            suspicion.event,
            suspicion.time,
            suspicion.ip,
            suspicion.protocol
        )

        cursor = self.connection.cursor()
        return cursor.execute(sql, values).lastrowid

    def delete(self, id: int) -> bool:
        cursor = self.connection.cursor()
        return cursor.execute("DELETE FROM suspicion WHERE suspicion_id = ?", (id,)).rowcount != 0

    @staticmethod
    def to_suspition(row):
        return Suspicion(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
        )


class FilterRule:
    def __init__(self, id, suspicion_id, name, enable_time, active):
        self.id = id
        self.suspicion_id = suspicion_id
        self.name = name
        self.enable_time = enable_time
        self.active = active

    @staticmethod
    def insertable(suspicion_id, name):
        return FilterRule(None, suspicion_id, name, None, None)



class RuleModel:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def from_file(path: str):
        connection = sqlite3.connect(path, isolation_level=None)
        return RuleModel(connection)

    def all(self, **args):
        sql = 'SELECT * FROM filter_rule'
        filters = []
        predicates = []

        active = bool(args.get('active', None))
        if active is not None:
            predicates.append('is_active = ?')
            filters.append(active)

        if predicates:
            sql = sql + ' WHERE ' + (' AND ').join(predicates)

        cursor = self.connection.cursor()

        return [
            RuleModel.to_rule(row) for row in cursor.execute(sql, tuple(filters))
        ]

    def by_id(self, id: int):

        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM filter_rule WHERE rule_id = ?', (id,))
        row = cursor.fetchone()

        return RuleModel.to_rule(row)

    def create(self, rule: FilterRule) -> int:
        cursor = self.connection.cursor()
        cursor.execute("SELECT 1 FROM suspicion WHERE suspicion_id = ?", (rule.suspicion_id,))
        row = cursor.fetchone()

        # suspicion_id not found
        if row is None:
            return None

        sql = """INSERT INTO filter_rule (suspicion_id, rule_name, enable_time)
         VALUES (?, ?, ?)"""

        values = (
            rule.suspicion_id,
            rule.name,
            datetime.datetime.now().isoformat()
        )

        cursor = self.connection.cursor()
        return cursor.execute(sql, values).lastrowid

    def delete(self, id: int) -> bool:
        cursor = self.connection.cursor()
        return cursor.execute("DELETE FROM filter_rule WHERE rule_id = ?", (id,)).rowcount != 0

    def deactivate(self, id: int) -> bool:
        cursor = self.connection.cursor()
        return cursor.execute("UPDATE filter_rule SET is_active = FALSE WHERE rule_id = ?", (id,)).rowcount != 0

    @staticmethod
    def to_rule(row):
        return FilterRule(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
        )


if __name__== '__main__':
    import datetime
    model = SuspicionModel.from_file("xwd.db")

    suspicion = Suspicion.insertable('http_flood', datetime.datetime.now().isoformat(), '123.123.123.123', 'tcp')
    print(model.create(suspicion))
    print(model.all())
    print(model.by_id(1))
    #print(model.delete(1))
    print(model.all())

    rule = FilterRule.insertable(1, 'blokuję natrętne IP')
    model = RuleModel.from_file("xwd.db")
    rule_id = model.create(rule)
    print('rule_id: ' + str(rule_id))
    print(model.all())
    print(model.by_id(1))
    #print(model.delete(1))
    print(model.all())
    print(model.all())

    model.deactivate(rule_id)

    print("active count: {}".format(len(model.all(active=True))))
    print("inactive count: {}".format(len(model.all(active=False))))
