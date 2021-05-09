from distutils.core import setup
from setuptools import find_packages
 
setup(name = 'SM3',     
      version = '1.0.0',  
      description = 'SM3 cryptographic hash algorithm',
      author = 'ice-bob',
      author_email = 'shanjie1997@gmail.com',
      url = '',
      license = 'MIT License',
      install_requires = [],
      classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Natural Language :: English (Simplified)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Utilities'
      ],
      keywords = '',
      packages = find_packages('src'),  
      package_dir = {'':'src'},         
      include_package_data = True,
)

