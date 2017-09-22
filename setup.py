from setuptools import setup

setup(
    name='nili',
    version='0.1.1',
    description='Nili is a Tool for Network Scan, Man in the Middle, Protocol Reverse Engineering and Fuzzing.',
    url='https://github.com/niloofarkheirkhah/nili',
    download_url ='https://github.com/niloofarkheirkhah/nili/archive/0.1.1.zip',
    author='Niloofar Kheirkhah - Ehsan Mir',
    author_email='niloofar.kheirkhah@gmail.com - ehsan.mir@icloud.com',
    license='GPLv3',
    classifiers=[
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    keywords='Security Test',
    packages=['nili'],
    entry_points={
        'console_scripts': ['nili=nili.__main__:main'],
    },
)
