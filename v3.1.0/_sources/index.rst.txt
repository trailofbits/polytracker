PolyTracker Documentation
=========================

PolyTracker is a tool originally created for the Automated Lexical Annotation and Navigation of Parsers, a backronym
devised solely for the purpose of referring to it as The ALAN Parsers Project. However, it has evolved into a general
purpose tool for efficiently performing data-flow and control-flow analysis of programs. PolyTracker is an LLVM pass
that instruments programs to track which bytes of an input file are operated on by which functions. It outputs a
database containing the data-flow information, as well as a runtime trace. PolyTracker also provides a Python library
for interacting with and analyzing its output, as well as an interactive Python REPL.

This documentation is primarily targeted toward developers wishing to integrate with the Python post-processing API.
For general usage instructions and documentation on how to compile an isntrumented program, see the `general README`_
on the `GitHub page`_.

.. _GitHub page: https://github.com/trailofbits/polytracker
.. _general README: https://github.com/trailofbits/polytracker/blob/master/README.md

.. toctree::
   :maxdepth: 4
   :caption: Contents:

   package

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
