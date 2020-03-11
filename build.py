import os

commands = """
python setup.py clean --all
python setup.py build sdist bdist_wheel
"""

for command in commands.splitlines():
    if command.isspace():
        continue
    os.system(command)
