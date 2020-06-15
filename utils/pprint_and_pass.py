import pprint

pp = pprint.PrettyPrinter(indent=4)


def print_and_pass(data):
    pp.pprint(data)
    print('\n'*2)
    return data

