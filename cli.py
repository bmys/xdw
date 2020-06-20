import argparse
from db_facade import SuspicionModel, Suspicion, FilterRule, RuleModel
from firewall_facade import *

DB = "xdw.db"

def parse_args(parser):
    subparsers = parser.add_subparsers(help='Commands')

    suspicions = subparsers.add_parser('suspicions', help='List all suspicions')
    suspicions.set_defaults(cmd='suspicions')

    create_rule = subparsers.add_parser('create-rule', help='Create iptables rule from suspicion')
    create_rule.add_argument('suspicion-id', metavar ='ID', help='Suspcion ID', action='store')
    create_rule.add_argument('--name', metavar ='text...', help='Rule name', required=False, action='store')
    create_rule.set_defaults(cmd='create_rule')

    return parser.parse_args()


def list_all_suspicions():
    model = SuspicionModel.from_file(DB)
    suspicions = model.all()

    for suspicion in suspicions:
        print(str(suspicion))

def handle(id, name):
    suspicion_model = SuspicionModel.from_file(DB)

    suspicion = suspicion_model.by_id(id)
    if not suspicion:
        print('Suspicion of id={} not found', id)
    else:
        print('Creating rule basing on suspicion:\n{}'.format(str(suspicion)))

    if name is None:
        name = 'created basing on suspicion_id={}'.format(id)

    rule = FilterRule.insertable(suspicion_id, name)

    if create_drop_rule(name, suspicion.ip):
        rule_model = RuleModel.from_file(DB)
        rule_model.create(rule)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='xdw managment utility', usage=argparse.SUPPRESS)

    args = None
    cmd = None

    try:
        args = parse_args(parser)
    except SystemExit:
        parser.print_help()

    cmd = getattr(args, 'cmd', None)
    
    if cmd == 'create_rule':
        suspicion_id = getattr(args, 'suspicion-id')
        name = getattr(args, 'name', None)

        handle(suspicion_id, name)
    elif cmd == 'suspicions':
        list_all_suspicions()
    else:
        parser.print_help()