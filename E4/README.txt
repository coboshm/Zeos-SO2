*** This tar file contains the following files:

* libjpread.a: Test suite for testing the read system call. It contains the user calls
  'runjp' and 'runjp_rank' to execute the tests plus all the necessary code to
  execute them.  
* libjpsbrk.a: Test suite for testing the sbrk system call. It contains the user calls
  'runjp' and 'runjp_rank' to execute the tests plus all the necessary code to
  execute them.  

*** Usage:

* You have to create a soft link named libjp.a pointing to the library with the
  tests that you want to run. Modify the Makefile so the user target is linked 
  with the libjp.a file.

* You have to call the 'runjp' routine from the main function of the user.c
  source file. 

* You can execute just a range of tests, replacing  the call to runjp() in the
  main function by a call to runjp_rank(int first, int last), where "first" is
  the identifier of the first test in the range that you want to execute, and
  "last" is the last one. Tests that not fall inside the rank will be evaluated 
  as SKIPPED.

* You should NOT modify the .bochsrc file that we have included in the tar file
  with the zeos base files. For example, if you modify the number of instruction
  per second that the virtual machine executes (ips), then some tests may fail.

* You have to take into account that the tests in a test suite are cumulative.
  That is, if one test fails then the execution of the rest of the tests may be
  inconsistent.

* You have to enable Bochs to write on the console, in order to read all the
  test messages without problems (this is already done in the system image that
  you use in the course laboratories).

