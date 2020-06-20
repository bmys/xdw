from iptc import Rule, Target, Table, Chain
from iptc.easy import decode_iptc_rule

def create_drop_rule(comment: str, ip: str) -> bool:
    chain = Chain(Table(Table.FILTER), "INPUT")

    for rule in chain.rules:
        if ip in rule.src:
            print("INPUT rule for IP={} exists; aborting".format(ip))
            return False

    drop_rule = Rule()
    drop_rule.src = ip

    comment_match = drop_rule.create_match("comment")
    comment_match.comment = comment

    drop_rule.add_match(comment_match)

    drop_rule.target = Target(drop_rule, "DROP")

    print("Creating rule: {}".format(decode_iptc_rule(drop_rule)))

    chain.insert_rule(drop_rule)

    return True

if __name__ == '__main__':
    create_drop_rule('test', '11.11.21.37')
