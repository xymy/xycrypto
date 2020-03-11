import argparse
import os

commands = """
python setup.py clean --all
python setup.py build sdist bdist_wheel
"""

parser = argparse.ArgumentParser()
parser.add_argument('--tag', action='store_true')
args = parser.parse_args()
if args.tag:
    from xycrypto import __version__
    commands += """
    git tag -a v{version} -m "xycrypto {version}"
    """.format(version=__version__)

for command in commands.splitlines():
    if command.isspace():
        continue
    os.system(command)
