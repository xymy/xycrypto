import argparse
import os


def main():
    parser = argparse.ArgumentParser(description='Build the xycrypto package.')
    parser.add_argument('-t', '--tag', action='store_true', help='add git tag')
    args = parser.parse_args()

    commands = [
        'python setup.py clean --all',
        'python setup.py build sdist bdist_wheel'
    ]

    if args.tag:
        from xycrypto import __version__
        commands.append('git tag -a v{version} -m "xycrypto {version}"'.format(
            version=__version__))

    for command in commands:
        os.system(command)


if __name__ == '__main__':
    main()
