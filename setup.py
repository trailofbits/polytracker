from setuptools import setup, find_packages

setup(
    name='polyprocess',
    description='A library and utility for processing and analyzing PolyTracker output',
    url='https://github.com/trailofbits/polytracker',
    author='Trail of Bits',
    version="0.1.0",
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'matplotlib',
        'networkX',
        'tqdm',
        'pygraphviz',
        'pydot',
        'typing_extensions'
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
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Utilities'
    ]
)
