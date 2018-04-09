def FlagsForFile( filename, **kwargs ):
  return {
    'flags': ['-I./depends/libsnark', '-I./depends/libsnark/depends/libff', '-I./depends/libsnark/depends/libfqfft','-std=c++11', '-Wall', '-Wextra','-Wfatal', '-errors','-pthread', 'CURVE_BN128=1']
  }
