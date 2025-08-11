from setuptools import setup, find_packages
import subprocess
import os


def _get_version_hash():
    """
    A way to get the version based on where the code is in git
    (So we don't have to rely on manual updating of the version
    field.)
    Returns: :string: The tag and hash of the commit on head.
    """
    if not os.path.isdir(".git"):
        print("This does not appear to be a Git repository.")
        return
    try:
        p = subprocess.Popen(["git", "describe",
                              "--tags", "--dirty", "--always"],
                             stdout=subprocess.PIPE)
    except EnvironmentError:
        print("unable to run git, leaving ecdsa/_version.py alone")
        return
    ver = p.communicate()[0]
    return ver.strip()


setup(
    name='python_dalton_s2s',
    #version=_get_version_hash(),
    version="1.0",
    description='Dalton Server-to-Server Authorization',
    url='https://github.com/turnercode/ids-server2server-py.git',
    author='IDS',
    license='WTFPL',
    packages=find_packages())
