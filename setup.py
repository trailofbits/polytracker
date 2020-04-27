from setuptools import setup, find_packages

setup(
    name='polyprocess',
    description='A utility to diff tree-like files such as JSON and XML.',
    url='https://github.com/trailofbits/polytracker',
    author='Trail of Bits',
    version="0.1.0",
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'matplotlib',
        'networkX',
        'tqdm',
        'pydot'
    ],
    entry_points={
        'console_scripts': [
            'polyprocess = polyprocess.__main__:main'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Utilities'
    ]
)