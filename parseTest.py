import argparse

def test():
    print('hihi')
    return 10

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Web Baseline Analyzer')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-r', action='store_true', help='Run script with this option to automatically perform remedies')
    group.add_argument('-e', action='extend', nargs='+', type=int, metavar=(1, 2), help='Enter list of sections to perform audit (E.g. 3 5 6)')
    group.add_argument('-d', action='extend', nargs='+', type=int, metavar=(1, 2), help='Enter list of sections to skip audit (E.g. 3 5 6)')

    args = parser.parse_args()
    print(args.r)

    testList = [test()]

    tes=testList[0]
    print(tes)